package cellscale

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
)

// fakeCell is one cell in memory: the OCI instances, the TerraBase members
// and a tenant load model. Each tenant lives on one node, so a new node is
// empty until a tenant moves to it, and a drained node's tenants move to the
// least loaded remaining nodes, as TerraBase would place them.
type fakeCell struct {
	mu        sync.Mutex
	cell      string
	instances []Instance
	state     map[string]NodeState
	release   map[string]string
	process   map[string]int
	samples   int64
	tenants   map[string][]TenantLoad
	now       func() time.Time
	advance   func(time.Duration)
	// New post-effect samples arrive after virtual time passes, including
	// the allowed node clock skew, without making simulated curves sleep.
	delayedSample map[string]bool
	// replicas overrides the full inventory for placement safety scenarios.
	replicas func() (ReplicaSnapshot, error)
	// scale multiplies every tenant's base request rate: the load curve.
	scale           float64
	coresPerRequest float64
	memoryGB        float64
	calls           []string
	failLaunch      error
	failList        error
	lag             map[string]uint64
	unread          map[string]bool
	// onResize runs after each resize and after[op] after a launch or
	// drain, to break the cell in the middle of an action.
	onResize func(node string)
	after    map[string]func(node string)
}

// waitTimeout bounds the controller's waits in tests: long enough for a
// wait that converges under a loaded race run, short enough for the many
// subtests that wait one out.
const waitTimeout = 200 * time.Millisecond

func newFakeCell(nodes int, shape Shape, tenantsPerNode int, rate float64) *fakeCell {
	f := &fakeCell{cell: "gru-1", state: map[string]NodeState{}, release: map[string]string{}, process: map[string]int{},
		tenants: map[string][]TenantLoad{}, now: time.Now, scale: 1, coresPerRequest: 1.0 / 2000, unread: map[string]bool{},
		delayedSample: map[string]bool{}}
	for n := 1; n <= nodes; n++ {
		name := NodeName(f.cell, n)
		f.instances = append(f.instances, Instance{ID: "ocid-" + name, Name: name, State: "RUNNING", Shape: shape})
		f.state[name], f.release[name] = StateReady, "r1"
		f.process[name] = 1
		for t := range tenantsPerNode {
			f.tenants[name] = append(f.tenants[name], TenantLoad{Project: project(fmt.Sprintf("org-%d-%d", n, t)), RequestRate: rate})
		}
	}
	return f
}

func (f *fakeCell) record(format string, values ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, values...))
}

func (f *fakeCell) List(context.Context) ([]Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	for index, instance := range f.instances {
		switch instance.State {
		case "STOPPING":
			f.instances[index].State = "STARTING"
		case "STARTING":
			f.instances[index].State = "RUNNING"
		}
	}
	instances := slices.Clone(f.instances)
	slices.SortFunc(instances, func(a, b Instance) int {
		x, _ := Ordinal(f.cell, a.Name)
		y, _ := Ordinal(f.cell, b.Name)
		return x - y
	})
	return instances, nil
}

func (f *fakeCell) Launch(_ context.Context, name string, shape Shape) (Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("launch %s %s", name, shape)
	if f.failLaunch != nil {
		return Instance{}, f.failLaunch
	}
	instance := Instance{ID: "ocid-" + name, Name: name, State: "RUNNING", Shape: shape}
	// OCI allocates a new OCID when a terminated node's name is reused.
	if f.process[name] > 0 {
		instance.ID = fmt.Sprintf("ocid-%s-generation-%d", name, f.process[name]+1)
	}
	f.instances = append(f.instances, instance)
	f.state[name], f.release[name] = StateJoining, "r1"
	f.process[name]++
	f.delayedSample[name] = true
	if hook := f.after["launch"]; hook != nil {
		hook(name)
	}
	return instance, nil
}

func (f *fakeCell) find(id string) int {
	return slices.IndexFunc(f.instances, func(i Instance) bool { return i.ID == id })
}

func (f *fakeCell) Resize(_ context.Context, id string, shape Shape) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.find(id)
	f.record("resize %s %s", f.instances[index].Name, shape)
	// OCI restarts the instance: it stops, starts and runs again over the
	// next two listings, unreadable meanwhile.
	f.instances[index].Shape, f.instances[index].State = shape, "STOPPING"
	f.process[f.instances[index].Name]++
	f.delayedSample[f.instances[index].Name] = true
	if f.onResize != nil {
		f.onResize(f.instances[index].Name)
	}
	return nil
}

func (f *fakeCell) Terminate(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.find(id)
	name := f.instances[index].Name
	f.record("terminate %s", name)
	if f.state[name] != StateDrained {
		return errors.New("terminate of an undrained node")
	}
	f.instances = slices.Delete(f.instances, index, index+1)
	return nil
}

func (f *fakeCell) Join(_ context.Context, identity NodeIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.matchesIdentity(identity) {
		return errors.New("join identity precondition failed")
	}
	node := identity.Name
	f.record("join %s", node)
	f.state[node] = StateReady
	f.delayedSample[node] = true
	return nil
}

func (f *fakeCell) Drain(_ context.Context, identity NodeIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.matchesIdentity(identity) {
		return errors.New("drain identity precondition failed")
	}
	node := identity.Name
	f.record("drain %s", node)
	for _, tenant := range f.tenants[node] {
		var coolest string
		for _, instance := range f.instances {
			if instance.Name != node && (coolest == "" || f.baseRate(instance.Name) < f.baseRate(coolest)) {
				coolest = instance.Name
			}
		}
		f.tenants[coolest] = append(f.tenants[coolest], tenant)
	}
	delete(f.tenants, node)
	f.state[node] = StateDrained
	f.delayedSample[node] = true
	if hook := f.after["drain"]; hook != nil {
		hook(node)
	}
	return nil
}

func (f *fakeCell) MoveTenant(_ context.Context, org string, source, destination NodeIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.matchesIdentity(source) || !f.matchesIdentity(destination) {
		return errors.New("move identity precondition failed")
	}
	from, to := source.Name, destination.Name
	f.record("move %s %s %s", org, from, to)
	index := slices.IndexFunc(f.tenants[from], func(t TenantLoad) bool { return t.Project == org })
	if index < 0 {
		return fmt.Errorf("tenant %s is not on %s", org, from)
	}
	f.tenants[to] = append(f.tenants[to], f.tenants[from][index])
	f.tenants[from] = slices.Delete(f.tenants[from], index, index+1)
	return nil
}

// Callers hold the cell mutex while enforcing the effect precondition.
func (f *fakeCell) matchesIdentity(identity NodeIdentity) bool {
	return slices.ContainsFunc(f.instances, func(instance Instance) bool {
		return !instance.Foreign && instance.Name == identity.Name && instance.ID == identity.InstanceID &&
			entityid.Derive("test-process", fmt.Sprintf("%s-p%d", instance.Name, f.process[instance.Name])) == identity.Incarnation
	})
}

func (f *fakeCell) baseRate(node string) float64 {
	total := 0.0
	for _, tenant := range f.tenants[node] {
		total += tenant.RequestRate
	}
	return total
}

// Pressure derives a valid contract report from the node's tenants.
func (f *fakeCell) Pressure(_ context.Context, node string) (NodePressure, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := slices.IndexFunc(f.instances, func(i Instance) bool { return i.Name == node })
	if index < 0 || f.unread[node] || !f.instances[index].Running() {
		return NodePressure{}, fmt.Errorf("node %s unreachable", node)
	}
	if f.delayedSample[node] && f.advance != nil {
		f.advance(MaxPressureClockSkew + time.Second)
		delete(f.delayedSample, node)
	}
	shape := f.instances[index].Shape
	requests := f.baseRate(node) * f.scale
	cpu := math.Min(1, requests*f.coresPerRequest/shape.OCPUs)
	var tenants []TenantLoad
	for _, tenant := range f.tenants[node] {
		tenant.RequestRate *= f.scale
		tenant.CPUShare = tenant.RequestRate / requests
		tenants = append(tenants, tenant)
	}
	slices.SortStableFunc(tenants, func(a, b TenantLoad) int { return cmp.Compare(b.RequestRate, a.RequestRate) })
	f.samples++
	pressure := NodePressure{Schema: PressureSchema, Node: node, InstanceID: f.instances[index].ID, State: f.state[node], Release: f.release[node],
		SampledAt: f.now().Add(time.Duration(f.samples)), ProcessID: entityid.Derive("test-process", fmt.Sprintf("%s-p%d", node, f.process[node])),
		CPUUtil: cpu, MemoryUtil: math.Min(1, f.memoryGB/shape.MemoryGB), DiskUsedBytes: 50 << 30, DiskTotalBytes: 500 << 30,
		DiskIOPS: requests / 2, RequestRate: requests, IOQueueDepth: requests / 2000, P95LatencyMS: 5 + 20*cpu,
		Load:       memberstatus.Load{Connections: uint64(requests / 10), StorageBytes: 50 << 30, ReplicationLagSeq: f.lag[node]},
		TopTenants: tenants[:min(len(tenants), MaxTopTenants)]}
	if err := pressure.Validate(); err != nil {
		panic(err)
	}
	return pressure, nil
}

// The load model assigns a tenant's requests to one node, while its replicas
// are prepared on every ready member before a drain. Tests can override the
// complete inventory to model individual under-replicated databases/shards.
func (f *fakeCell) Replicas(context.Context, string) (ReplicaSnapshot, error) {
	if f.replicas != nil {
		return f.replicas()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	snapshot := ReplicaSnapshot{Schema: 1, Cell: f.cell, SampledAt: f.now(), Complete: true,
		Members: []NodeIdentity{}, Placements: []ReplicaPlacement{}}
	var replicas []string
	for _, instance := range f.instances {
		if !instance.Foreign {
			snapshot.Members = append(snapshot.Members, NodeIdentity{Name: instance.Name, InstanceID: instance.ID, Incarnation: entityid.Derive("test-process", fmt.Sprintf("%s-p%d", instance.Name, f.process[instance.Name]))})
		}
		if !instance.Foreign && instance.Running() && f.state[instance.Name] == StateReady && !f.unread[instance.Name] {
			replicas = append(replicas, instance.Name)
		}
	}
	for _, tenants := range f.tenants {
		for _, tenant := range tenants {
			snapshot.Placements = append(snapshot.Placements, ReplicaPlacement{Org: tenant.Project, Database: entityid.Derive("test-database", "db"), Shard: 1,
				LiveReplicas: slices.Clone(replicas)})
		}
	}
	return snapshot, nil
}

// memberIdentities is the actual membership of a newly measured inventory.
func (f *fakeCell) memberIdentities() []NodeIdentity {
	f.mu.Lock()
	defer f.mu.Unlock()
	members := []NodeIdentity{}
	for _, instance := range f.instances {
		if !instance.Foreign {
			members = append(members, NodeIdentity{Name: instance.Name, InstanceID: instance.ID,
				Incarnation: entityid.Derive("test-process", fmt.Sprintf("%s-p%d", instance.Name, f.process[instance.Name]))})
		}
	}
	return members
}

func (f *fakeCell) setScale(scale float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scale = scale
}

func (f *fakeCell) nodes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.instances)
}

func (f *fakeCell) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func testPolicy() Policy {
	return Policy{Nodes: autoscale.Bounds{Min: 3, Max: 6}, ReplicationFactor: 3, MaxReplicationLagSeq: 1000,
		Shape: ShapeBounds{MinOCPUs: 2, MaxOCPUs: 8, StepOCPUs: 2, MemoryGBPerOCPU: 6},
		Targets: Targets{CPUUtil: 0.7, MemoryUtil: 0.8, DiskUtil: 0.75, DiskIOPS: 3000, RequestRate: 2000,
			IOQueueDepth: 8, P95LatencyMS: 50},
		ScaleDownBelow: 0.6, SustainUpSeconds: 300, SustainDownSeconds: 1800, CooldownSeconds: 600,
		ScaleDownCooldownSeconds: 1800, MaxActionsPerHour: 4, MonthlyBudget: 2000,
		Prices: Prices{OCPUHour: 0.01, MemoryGBHour: 0.0015, NodeMonthly: 10}, MaxFailures: 3}
}

var small = Shape{OCPUs: 2, MemoryGB: 12}

// journal captures decisions instead of logging them.
type journal struct {
	mu        sync.Mutex
	decisions []decisionlog.Decision
}

func (j *journal) Record(_ context.Context, decision decisionlog.Decision) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	decision.ID = fmt.Sprintf("d%d", len(j.decisions)+1)
	j.decisions = append(j.decisions, decision)
	return decision.ID
}

func captureJournal(t *testing.T) *journal {
	t.Helper()
	j := &journal{}
	t.Cleanup(decisionlog.SetDefault(j))
	return j
}

// sim drives a controller over a fake cell with a stepped clock.
type sim struct {
	t          *testing.T
	cell       *fakeCell
	controller *Controller
	start, now time.Time
	step       time.Duration
}

type stepAction struct {
	at     time.Duration
	action Action
}

func newSim(t *testing.T, policy Policy, cell *fakeCell, step time.Duration) *sim {
	t.Helper()
	start := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	s := &sim{t: t, cell: cell, start: start, now: start.Add(-MaxPressureClockSkew - time.Second), step: step}
	cell.now = func() time.Time { return s.now }
	cell.advance = func(elapsed time.Duration) { s.now = s.now.Add(elapsed) }
	controller, err := New(Config{Cell: cell.cell, Policy: policy, Cloud: cell, Members: cell, Source: cell,
		Now: func() time.Time { return s.now }, Poll: time.Millisecond, ReadyTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// Begin curves after startup telemetry can be measured, without cooldown.
	s.now = start
	controller.history = History{}
	s.controller = controller
	controller.config.Members = liveReplicaInventory{cell, controller}
	return s
}

// run ticks steps times, setting the load curve's scale before each tick,
// and returns the non-hold actions with their offsets from the start.
func (s *sim) run(steps int, curve func(at time.Duration) float64) []stepAction {
	s.t.Helper()
	var acted []stepAction
	for range steps {
		at := s.now.Sub(s.start)
		s.cell.setScale(curve(at))
		action, err := s.controller.Tick(s.t.Context())
		if err != nil {
			s.t.Fatalf("tick at %s: %v (calls %v)", at, err, s.cell.callLog())
		}
		if action.Kind != KindHold {
			acted = append(acted, stepAction{at: at, action: action})
		}
		s.now = s.now.Add(s.step)
	}
	return acted
}

func (s *sim) observe() State {
	s.t.Helper()
	state, err := s.controller.observe(s.t.Context())
	if err != nil {
		s.t.Fatal(err)
	}
	return state
}

func kinds(acted []stepAction) []string {
	var out []string
	for _, a := range acted {
		out = append(out, fmt.Sprintf("%s %s %s %s@%s", a.action.Kind, a.action.Node, a.action.Tenant, a.action.Target, a.at))
	}
	return out
}

// Each fake node starts with four tenants of 250 requests/s: 1000 requests/s
// per node is 0.5 request pressure and 0.36 CPU pressure at 2 OCPUs.

func TestCurveShortSpikeDoesNotScale(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	acted := newSim(t, testPolicy(), cell, time.Minute).run(90, func(at time.Duration) float64 {
		if at >= 30*time.Minute && at < 34*time.Minute {
			return 3 // 4 minutes of triple load, shorter than the 5 minute sustain
		}
		return 1
	})
	if len(acted) != 0 {
		t.Fatalf("a spike shorter than the sustain window acted: %v", kinds(acted))
	}
}

func TestCurveSustainedCPUResizesOnce(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	// CPU-heavy requests: 1000 requests/s use 2 cores, 1.43 CPU pressure at
	// 2 OCPUs while request pressure stays at 0.5.
	cell.coresPerRequest = 1.0 / 500
	acted := newSim(t, testPolicy(), cell, time.Minute).run(90, func(time.Duration) float64 { return 1 })
	if len(acted) != 1 || acted[0].action.Kind != KindResize || acted[0].action.To != (Shape{OCPUs: 4, MemoryGB: 24}) ||
		acted[0].at != 5*time.Minute+MaxPressureClockSkew+time.Second {
		t.Fatalf("sustained CPU pressure actions = %v", kinds(acted))
	}
	want := []string{"resize gru-1-db-1 4 OCPU/24 GB", "resize gru-1-db-2 4 OCPU/24 GB", "resize gru-1-db-3 4 OCPU/24 GB"}
	if got := cell.callLog(); !slices.Equal(got, want) {
		t.Fatalf("rolling resize calls = %v, want %v", got, want)
	}
}

func TestCurveSustainedRequestsScaleOutAndFillNewNode(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	acted := newSim(t, testPolicy(), cell, time.Minute).run(120, func(time.Duration) float64 { return 2.6 })
	// 2600 requests/s per node is 1.3 request pressure: the cell adds an
	// empty node, then moves one tenant off each hot node onto it.
	if len(acted) < 2 || acted[0].action.Kind != KindScaleOut || acted[0].action.Node != "gru-1-db-4" {
		t.Fatalf("sustained request actions = %v", kinds(acted))
	}
	for _, a := range acted[1:] {
		if a.action.Kind != KindRebalance || a.action.Target != "gru-1-db-4" {
			t.Fatalf("after the scale out every action should fill the new node: %v", kinds(acted))
		}
	}
	if cell.nodes() != 4 {
		t.Fatalf("nodes = %d, want 4", cell.nodes())
	}
	for _, name := range []string{"gru-1-db-1", "gru-1-db-2", "gru-1-db-3", "gru-1-db-4"} {
		if rate := cell.baseRate(name) * 2.6; rate >= 2000 {
			t.Fatalf("node %s still serves %.0f requests/s, above its 2000 target", name, rate)
		}
	}
	log := cell.callLog()
	if !slices.Equal(log[:2], []string{"launch gru-1-db-4 2 OCPU/12 GB", "join gru-1-db-4"}) {
		t.Fatalf("scale out calls = %v", log)
	}
}

func TestCurveDiurnalFollowsLoadWithoutFlapping(t *testing.T) {
	captureJournal(t)
	policy := testPolicy()
	cell := newFakeCell(3, small, 8, 125)
	s := newSim(t, policy, cell, 5*time.Minute)
	// 0.4x at midnight to 2.6x at noon of the 3000 requests/s base, for two days.
	curve := func(at time.Duration) float64 {
		return 1.5 - 1.1*math.Cos(2*math.Pi*float64(at%(24*time.Hour))/float64(24*time.Hour))
	}
	low, high := cell.nodes(), cell.nodes()
	var acted []stepAction
	for range 2 * 288 {
		acted = append(acted, s.run(1, curve)...)
		low, high = min(low, cell.nodes()), max(high, cell.nodes())
	}
	if low != policy.Nodes.Min || high < 4 || high > policy.Nodes.Max {
		t.Fatalf("diurnal nodes ranged %d..%d: %v", low, high, kinds(acted))
	}
	outs, ins := 0, 0
	for index, a := range acted {
		switch a.action.Kind {
		case KindScaleOut:
			outs++
		case KindScaleIn:
			ins++
		}
		// The opposite direction never follows within the scale-down cooldown.
		if index > 0 && a.action.up() != acted[index-1].action.up() && a.at-acted[index-1].at < 30*time.Minute {
			t.Fatalf("flapped at %s: %v", a.at, kinds(acted))
		}
	}
	if outs < 2 || ins < 2 || len(acted) > 40 {
		t.Fatalf("two days took %d scale outs, %d scale ins, %d actions: %v", outs, ins, len(acted), kinds(acted))
	}
	if cell.nodes() != policy.Nodes.Min {
		t.Fatalf("the second night ended with %d nodes", cell.nodes())
	}
}

func TestCurveNoisyTenantMovesInsteadOfScaling(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 200)
	// A hobby tenant on db-2 sends 1300 requests/s: db-2 runs at 2100, 1.05
	// request pressure, while db-1 and db-3 idle at 800.
	cell.tenants["gru-1-db-2"] = append(cell.tenants["gru-1-db-2"], TenantLoad{Project: project("noisy"), RequestRate: 1300})
	cell.tenants["gru-1-db-1"] = cell.tenants["gru-1-db-1"][:2]
	acted := newSim(t, testPolicy(), cell, time.Minute).run(60, func(time.Duration) float64 { return 1 })
	if len(acted) != 1 || acted[0].action.Kind != KindRebalance || acted[0].action.Tenant != project("noisy") ||
		acted[0].action.Node != "gru-1-db-2" || acted[0].action.Target != "gru-1-db-1" {
		t.Fatalf("noisy tenant actions = %v (%+v)", kinds(acted), acted)
	}
}
