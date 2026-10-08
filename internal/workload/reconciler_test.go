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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
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
	return authority.Snapshot{Leader: f.leader, Ready: true, Epoch: f.epoch, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}

func (f *fakeFencer) Guard(context.Context, uint64) error {
	if f.fenced {
		return authority.ErrFenced
	}
	return nil
}

type capacityRecorder struct {
	requests  []placement.WorkloadRequest
	satisfied int
}

func (c *capacityRecorder) CapacitySatisfied(ServiceSpec) { c.satisfied++ }

func (c *capacityRecorder) RequestCapacity(_ ServiceSpec, request placement.WorkloadRequest) {
	c.requests = append(c.requests, request)
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

func TestReconcilerConvergedServiceIsIdle(t *testing.T) {
	cell := threeHostCell()
	for _, node := range []string{"node-a", "node-b"} {
		cell.seed(node, "api", testDigest, 4)
	}
	cell.runAll()
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(1, 5))
	if err := reconciler.Tick(context.Background()); err != nil || len(cell.writes) != 0 {
		t.Fatalf("converged tick wrote %v (%v)", cell.writes, err)
	}
	if last := reconciler.Last()["api"]; last.Replicas != 2 || last.Target != 2 || last.Reason != "self-heal" {
		t.Fatalf("result = %#v", last)
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

func TestReconcilerEnforcesBoundsWithinRolloutLimits(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	spec := statelessSpec(3, 5)
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, spec)
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); len(got) != 2 {
		t.Fatalf("surge 1 should add one replica per step, active = %v", got)
	}
	cell.runAll()
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); len(got) != 3 {
		t.Fatalf("active after second step = %v", got)
	}

	// Lower bound above the active count: scale down one ready replica per
	// step and only once nothing is starting.
	cell.runAll()
	for _, node := range []string{"node-d"} {
		cell.seed(node, "api", testDigest, 6)
		cell.run(node, "api", "running")
	}
	cell.writes = nil
	down := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(1, 2))
	if err := down.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); len(got) != 3 || len(cell.writes) != 1 || !cell.writes[0].Withdrawn {
		t.Fatalf("scale-down step = %v, writes %v", got, cell.writes)
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

type resettableSignals struct {
	autoscale.Source
	resets int
}

func (s *resettableSignals) Reset() { s.resets++ }

// Every new authority term resets a resettable signal source once, so a
// returning leader never scales on samples from its earlier term.
func TestReconcilerNewTermResetsSignalSource(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	signals := &resettableSignals{Source: autoscale.NewWindowStore(time.Hour, 100)}
	fencer := &fakeFencer{leader: true, epoch: 1}
	reconciler := newTestReconciler(t, cell, fencer, statelessSpec(1, 4), func(c *Config) { c.Signals = signals })
	for range 2 {
		if err := reconciler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	fencer.epoch = 2
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if signals.resets != 2 {
		t.Fatalf("resets = %d, want one per term", signals.resets)
	}
}

func TestReconcilerAuthorityChangeResetsHistory(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.seed("node-b", "api", testDigest, 4)
	cell.runAll()
	spec := statelessSpec(1, 4)
	spec.Scaling = &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}},
		UpCooldownSeconds: 300}
	store := autoscale.NewWindowStore(time.Hour, 100)
	store.Record(autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}, autoscale.SignalCPUUtilization,
		autoscale.Sample{At: testNow, Value: 0.9})
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 2}, spec, func(c *Config) { c.Signals = store })
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cell.writes) != 0 || reconciler.Last()["api"].Reason != autoscale.ReasonScaleUpCooldown {
		t.Fatalf("new authority term scaled before its cooldown: %#v", reconciler.Last()["api"])
	}
}

func TestReconcilerNeverUsesDedicatedTerraBaseHosts(t *testing.T) {
	cell := newFakeCell()
	cell.addHost("node-a", "fd-1", true)
	cell.addHost("tb-1", "fd-2", true, func(r *host.Registration) {
		r.ManagedPlacement = &host.ManagedPlacementBinding{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "0000000000KJ432RJ85B7APRW2", SeatID: "0000000000XG8SBD7XGE97V28G"}
	})
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	capacity := &capacityRecorder{}
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(2, 2),
		func(c *Config) { c.Capacity = capacity })
	err := reconciler.Tick(context.Background())
	if !errors.Is(err, placement.ErrInsufficientCapacity) || len(cell.writes) != 0 {
		t.Fatalf("Tick = %v, writes %v", err, cell.writes)
	}
	if len(capacity.requests) != 1 || capacity.requests[0].Replicas != 2 {
		t.Fatalf("capacity requests = %#v", capacity.requests)
	}
	for _, candidate := range capacity.requests[0].Hosts {
		if candidate.Node == "tb-1" {
			t.Fatal("dedicated TerraBase host offered as a candidate")
		}
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

func TestReconcilerWaitsForReleaseAndHoldsExhaustedGenerations(t *testing.T) {
	cell := threeHostCell()
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(2, 3))
	if err := reconciler.Tick(context.Background()); err != nil || reconciler.Last()["api"].Reason != "awaiting-release" {
		t.Fatalf("no release: %#v (%v)", reconciler.Last()["api"], err)
	}
	exhausted, _ := ReleaseGeneration(5)
	exhausted += 1<<ReleaseShift - 1
	cell.seed("node-a", "api", testDigest, exhausted)
	cell.runAll()
	if err := reconciler.Tick(context.Background()); !errors.Is(err, ErrGenerationSpace) || len(cell.writes) != 0 {
		t.Fatalf("exhausted release = %v, writes %v", err, cell.writes)
	}
}

func TestReconcilerDomainCapRequestsCapacity(t *testing.T) {
	cell := newFakeCell()
	cell.addHost("node-a", "fd-1", true)
	cell.addHost("node-b", "fd-1", true)
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	spec := statelessSpec(2, 2)
	spec.Placement.MaxPerFailureDomain = 1
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, spec)
	if err := reconciler.Tick(context.Background()); !errors.Is(err, placement.ErrInsufficientCapacity) || len(cell.writes) != 0 {
		t.Fatalf("domain cap = %v, writes %v", err, cell.writes)
	}
}

func TestReleaseShapeKeepsCurrentScale(t *testing.T) {
	spec := statelessSpec(2, 6)
	generation, replicas, err := ReleaseShape(spec, 9, 1, Observation{})
	if err != nil || generation != 9<<ReleaseShift || replicas != 2 {
		t.Fatalf("first release = %d/%d (%v)", generation, replicas, err)
	}
	observation := Observation{Active: map[string]host.Desired{"a": {}, "b": {}, "c": {}, "d": {}}}
	if _, replicas, _ := ReleaseShape(spec, 10, 2, observation); replicas != 4 {
		t.Fatalf("later release replicas = %d", replicas)
	}
	if _, _, err := ReleaseShape(spec, maxRelease+1, 2, observation); !errors.Is(err, ErrGenerationSpace) {
		t.Fatalf("oversized release accepted: %v", err)
	}
}

func TestObserveExcludesDedicatedHostsAndSubtractsReserve(t *testing.T) {
	cell := newFakeCell()
	cell.addHost("node-a", "FD-1", true, func(r *host.Registration) { r.SystemReserveBytes = 4 << 30 })
	cell.addHost("tb-1", "fd-2", true, func(r *host.Registration) {
		r.ManagedMember = &host.ManagedMemberBinding{HostAttempt: 1}
	})
	cell.seed("node-a", "worker", testDigest, 1)
	cell.seed("tb-1", "terrabase", testDigest, 1) // no profile, but on a dedicated host
	hosts, _ := cell.ListHosts(context.Background())
	desired, _ := cell.ListDesired(context.Background(), "")
	observation, err := Observe(Snapshot{Cell: "gru", Environment: "prod", Role: "api", Hosts: hosts,
		Desired: desired, Profiles: testProfiles, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Candidates) != 1 {
		t.Fatalf("candidates = %#v", observation.Candidates)
	}
	candidate := observation.Candidates[0]
	if candidate.FailureDomain != "fd-1" || candidate.Capacity.MemoryBytes != 12<<30 || candidate.Allocated != testProfile {
		t.Fatalf("candidate = %#v", candidate)
	}
	if observation.HighWater != 0 || len(observation.Statuses) != 2 {
		t.Fatalf("observation = %#v", observation)
	}

	desired = append(desired, host.Desired{Cell: "fra", Node: "node-a", Role: "api"})
	if _, err := Observe(Snapshot{Cell: "gru", Environment: "prod", Role: "api", Hosts: hosts, Desired: desired,
		Profiles: testProfiles, Now: testNow}); err == nil {
		t.Fatal("cross-cell allocation accepted")
	}
	hosts[0].Verified = false
	if _, err := Observe(Snapshot{Cell: "gru", Environment: "prod", Role: "api", Hosts: hosts, Now: testNow}); err == nil {
		t.Fatal("unverified host accepted")
	}
}

func TestReconcilerKeepsScaleDuringPartialRollout(t *testing.T) {
	cell := threeHostCell()
	oldRelease, _ := ReleaseGeneration(2)
	newRelease, _ := ReleaseGeneration(3)
	// A release interrupted after its first write: one new replica is ready
	// and two old replicas still serve.
	cell.seed("node-a", "api", newDigest, newRelease)
	cell.seed("node-b", "api", testDigest, oldRelease)
	cell.seed("node-c", "api", testDigest, oldRelease)
	cell.runAll()
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(1, 3))
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); len(got) < 3 {
		t.Fatalf("partial rollout shrank the service to %v (writes %v)", got, cell.writes)
	}
	if last := reconciler.Last()["api"]; last.Replicas != 3 || last.Target != 3 {
		t.Fatalf("result = %#v", last)
	}
	// Surge replicas must not raise the goal: the rollout converges back to
	// three replicas of the new release.
	for range 10 {
		cell.runAll()
		if err := reconciler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := cell.active("api"); len(got) < 3 {
			t.Fatalf("rollout shrank the service to %v", got)
		}
	}
	got := cell.active("api")
	if len(got) != 3 {
		t.Fatalf("rollout settled at %v", got)
	}
	for _, node := range got {
		if cell.desired[node+"/api"].Digest != newDigest {
			t.Fatalf("stale replica left on %s", node)
		}
	}
}

func TestReconcilerScaleUpIsNotTruncatedBySurge(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.seed("node-b", "api", testDigest, 4)
	cell.runAll()
	spec := statelessSpec(1, 4)
	spec.Scaling = &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}},
		UpCooldownSeconds: 600}
	store := autoscale.NewWindowStore(time.Hour, 100)
	store.Record(autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"}, autoscale.SignalCPUUtilization,
		autoscale.Sample{At: testNow, Value: 0.9})
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, spec, func(c *Config) { c.Signals = store })
	// The first tick only seeds the authority term's cooldown.
	reconciler.mu.Lock()
	reconciler.epoch = 1
	reconciler.history["api"] = autoscale.History{}
	reconciler.mu.Unlock()
	for range 4 {
		if err := reconciler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		cell.runAll()
	}
	if got := cell.active("api"); len(got) != 4 {
		t.Fatalf("scale-up to 4 with surge 1 stopped at %v (last %#v)", got, reconciler.Last()["api"])
	}
}

// Two services that each need one more replica must not both claim the last
// free slot on a host: each plans against the writes earlier services
// committed in the same tick.
func TestReconcilerServicesDoNotOvercommitOneHost(t *testing.T) {
	cell := newFakeCell()
	cell.addHost("node-a", "fd-1", true)
	cell.addHost("node-b", "fd-2", true, func(r *host.Registration) { r.Capacity.CPU = 2 })
	release, _ := ReleaseGeneration(1)
	cell.seed("node-a", "api", testDigest, release)
	cell.seed("node-a", "worker", testDigest, release)
	cell.runAll()
	worker := statelessSpec(2, 2)
	worker.Role = "worker"
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(2, 2),
		func(config *Config) { config.Specs = append(config.Specs, worker) })
	err := reconciler.Tick(context.Background())
	onB := 0
	for _, write := range cell.writes {
		if write.Node == "node-b" && !write.Withdrawn {
			onB++
		}
	}
	if onB != 1 || !errors.Is(err, placement.ErrInsufficientCapacity) {
		t.Fatalf("node-b received %d allocations (err %v), want exactly one and a capacity error", onB, err)
	}
}

// A node whose old-release replica still serves is not a free surge slot:
// replacing it in place waits until no new replica is starting.
func TestReconcilerDoesNotReplaceServingStaleReplicaWhileStarting(t *testing.T) {
	cell := newFakeCell()
	cell.addHost("node-a", "fd-1", true)
	cell.addHost("node-b", "fd-2", true)
	oldRelease, _ := ReleaseGeneration(2)
	newRelease, _ := ReleaseGeneration(3)
	cell.seed("node-a", "api", newDigest, newRelease)
	cell.seed("node-b", "api", testDigest, oldRelease)
	cell.run("node-a", "api", "starting")
	cell.run("node-b", "api", "running")
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(2, 2))
	if err := reconciler.Tick(context.Background()); err != nil || len(cell.writes) != 0 {
		t.Fatalf("the last serving replica was replaced while the new one starts: %v (%v)", cell.writes, err)
	}
	cell.run("node-a", "api", "running")
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cell.writes) != 1 || cell.writes[0].Node != "node-b" || cell.writes[0].Withdrawn ||
		cell.writes[0].Digest != newDigest {
		t.Fatalf("writes = %#v, want one in-place replacement on node-b", cell.writes)
	}
}

// A replacement step commits its addition before the failed replica's
// withdrawal, so a failed addition never leaves the role without the active
// allocation that templates new replicas.
func TestReconcilerKeepsReleaseTemplateWhenAdditionFails(t *testing.T) {
	cell := newFakeCell()
	cell.addHost("node-a", "fd-1", true)
	cell.addHost("node-b", "fd-2", true)
	release, _ := ReleaseGeneration(4)
	cell.seed("node-a", "api", testDigest, release)
	cell.run("node-a", "api", "failed")
	cell.failOn = "node-b"
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(1, 1))
	if err := reconciler.Tick(context.Background()); err == nil {
		t.Fatal("injected addition failure was not reported")
	}
	if got := cell.active("api"); !slices.Equal(got, []string{"node-a"}) {
		t.Fatalf("active = %v: the template replica was withdrawn before its replacement committed", got)
	}
	reconciler.mu.Lock()
	_, remembered := reconciler.goal["api"]
	reconciler.mu.Unlock()
	if remembered {
		t.Fatal("a failed step advanced the remembered goal")
	}
	cell.failOn = ""
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); !slices.Equal(got, []string{"node-b"}) {
		t.Fatalf("active after retry = %v", got)
	}
}

// Retained replicas past the failure-domain cap are migrated to a domain
// with room instead of being rejected every tick.
func TestReconcilerMigratesPastDomainCap(t *testing.T) {
	cell := newFakeCell()
	cell.addHost("node-a", "fd-1", true)
	cell.addHost("node-b", "fd-1", true)
	cell.addHost("node-c", "fd-2", true)
	release, _ := ReleaseGeneration(1)
	cell.seed("node-a", "api", testDigest, release)
	cell.seed("node-b", "api", testDigest, release)
	cell.runAll()
	spec := statelessSpec(2, 2)
	spec.Placement.MaxPerFailureDomain = 1
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, spec)
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cell.writes) != 1 || cell.writes[0].Node != "node-c" || cell.writes[0].Withdrawn {
		t.Fatalf("writes = %#v, want a new replica in fd-2", cell.writes)
	}
	cell.runAll()
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); len(got) != 2 || !slices.Contains(got, "node-c") {
		t.Fatalf("active = %v, want one replica per domain", got)
	}
}

// A newer release of the same role in another environment neither
// supersedes this environment's release nor stalls its self-healing.
func TestReconcilerIgnoresOtherEnvironmentsRelease(t *testing.T) {
	cell := threeHostCell()
	cell.addHost("node-s", "fd-1", true, func(r *host.Registration) { r.Environment = "staging" })
	prod, _ := ReleaseGeneration(2)
	staging, _ := ReleaseGeneration(9)
	cell.seed("node-a", "api", testDigest, prod)
	cell.desired["node-s/api"] = host.Desired{Cell: "gru", Node: "node-s", Environment: "staging", Role: "api",
		Digest: newDigest, Generation: staging, AuthorityEpoch: 1}
	cell.runAll()
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(2, 2))
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cell.writes) != 1 || cell.writes[0].Generation != prod+1 || cell.writes[0].Digest != testDigest {
		t.Fatalf("writes = %#v, want one prod replica at generation %d", cell.writes, prod+1)
	}
}

// Stateful specs are never reconciled here, so they need no generic profile.
func TestNewAcceptsStatefulSpecWithoutGenericProfile(t *testing.T) {
	if _, err := New(Config{Cell: "gru", Specs: []ServiceSpec{statelessSpec(1, 2), validStateful()},
		Profiles: testProfiles, Hosts: newFakeCell(), Writer: newFakeCell(), Fencer: &fakeFencer{}}); err != nil {
		t.Fatalf("New with a stateful spec = %v", err)
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

func TestReconcilerSetServicesAddsAndRemovesRoles(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	hosts := &countingHosts{fakeCell: cell}
	reconciler, err := New(Config{Cell: "gru", Hosts: hosts, Writer: cell, Fencer: &fakeFencer{leader: true, epoch: 1},
		Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Tick(context.Background()); err != nil || hosts.listed.Load() != 0 || len(cell.writes) != 0 {
		t.Fatalf("empty reconciler listed hosts %d times, wrote %v (%v)", hosts.listed.Load(), cell.writes, err)
	}
	if _, owns := reconciler.Owns("api"); owns {
		t.Fatal("empty reconciler owns api")
	}

	if err := reconciler.SetServices([]ServiceSpec{statelessSpec(3, 5)}, testProfiles); err != nil {
		t.Fatal(err)
	}
	if _, owns := reconciler.Owns("api"); !owns {
		t.Fatal("added role not owned")
	}
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cell.active("api"); len(got) < 2 {
		t.Fatalf("active = %v, want scale up toward the new minimum", got)
	}
	if _, reported := reconciler.Last()["api"]; !reported {
		t.Fatal("added role has no result")
	}

	if err := reconciler.SetServices(nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, owns := reconciler.Owns("api"); owns {
		t.Fatal("removed role still owned")
	}
	if len(reconciler.Last()) != 0 {
		t.Fatalf("removed role still reported: %v", reconciler.Last())
	}
}

func TestReconcilerSetServicesRejectsInvalidInput(t *testing.T) {
	cell := threeHostCell()
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(1, 5))
	bad := statelessSpec(1, 5)
	bad.Replicas = ReplicaBounds{Min: 5, Max: 1}
	for name, err := range map[string]error{
		"invalid spec":    reconciler.SetServices([]ServiceSpec{bad}, testProfiles),
		"missing profile": reconciler.SetServices([]ServiceSpec{statelessSpec(1, 5)}, nil),
	} {
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	spec, owns := reconciler.Owns("api")
	if !owns || spec.Replicas.Max != 5 {
		t.Fatalf("previous services not kept: %#v %v", spec, owns)
	}
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatalf("tick after rejected amendment: %v", err)
	}
}

func TestReconcilerSetServicesWhileTicking(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	reconciler := newTestReconciler(t, cell, &fakeFencer{leader: true, epoch: 1}, statelessSpec(1, 5))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 50 {
			specs := []ServiceSpec{statelessSpec(1, 5)}
			if i%2 == 0 {
				specs = nil
			}
			if err := reconciler.SetServices(specs, testProfiles); err != nil {
				t.Error(err)
			}
		}
	}()
	for range 50 {
		_ = reconciler.Tick(context.Background())
		reconciler.Owns("api")
		reconciler.Last()
	}
	wg.Wait()
}

// replacingWriter starts replacing the reconciler's services during its
// first write, as a cell spec adopted mid-tick does.
type replacingWriter struct {
	*fakeCell
	replace func()
}

func (w *replacingWriter) ApplyDesired(ctx context.Context, d host.Desired) (host.Receipt, error) {
	receipt, err := w.fakeCell.ApplyDesired(ctx, d)
	if replace := w.replace; replace != nil {
		w.replace = nil
		go replace()
		// Let the replacement block on the in-flight write.
		time.Sleep(50 * time.Millisecond)
	}
	return receipt, err
}

// A tick stops writing once its services are replaced, so a removed role is
// never given replicas by a tick that started before its removal.
func TestReconcilerStopsWritingWhenServicesAreReplaced(t *testing.T) {
	cell := threeHostCell()
	cell.seed("node-a", "api", testDigest, 4)
	cell.runAll()
	spec := statelessSpec(3, 5)
	spec.Rollout.MaxSurge = 3
	writer := &replacingWriter{fakeCell: cell}
	reconciler, err := New(Config{Cell: "gru", Specs: []ServiceSpec{spec}, Profiles: testProfiles, Hosts: cell,
		Writer: writer, Fencer: &fakeFencer{leader: true, epoch: 1}, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	replaced := make(chan error, 1)
	writer.replace = func() { replaced <- reconciler.SetServices(nil, nil) }
	if err := reconciler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	if len(cell.writes) != 1 || len(reconciler.Last()) != 0 {
		t.Fatalf("writes %v, results %v after the services were replaced", cell.writes, reconciler.Last())
	}
}
