package nodescale

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// fakePool keeps instances in memory: Grow adds one unnamed inst-… instance, Remove deletes one.
type fakePool struct {
	now       func() time.Time
	exists    bool
	instances []PoolInstance
	grown     int
}

func (p *fakePool) Observe(context.Context) (PoolState, error) {
	if !p.exists {
		return PoolState{}, nil
	}
	return PoolState{Exists: true, PoolID: "pool", LifecycleState: "RUNNING", Size: len(p.instances),
		Instances: slices.Clone(p.instances)}, nil
}

func (p *fakePool) Ensure(ctx context.Context, _ Recipe) (PoolState, error) {
	p.exists = true
	return p.Observe(ctx)
}

func (p *fakePool) Grow(_ context.Context, from int) error {
	switch size := len(p.instances); size {
	case from + 1:
		return nil
	case from:
	default:
		return fmt.Errorf("%w: pool is %d, expected %d", ErrPoolChanged, size, from)
	}
	p.grown++
	p.instances = append(p.instances, PoolInstance{ID: fmt.Sprintf("ocid-inst-%d", p.grown),
		Name: fmt.Sprintf("inst-%d", p.grown), State: "PROVISIONING", PrivateIP: fmt.Sprintf("10.0.9.%d", p.grown),
		Created: p.now()})
	return nil
}

func (p *fakePool) Name(_ context.Context, id, node string) error {
	i := slices.IndexFunc(p.instances, func(in PoolInstance) bool { return in.ID == id })
	if i < 0 {
		return ErrNotPoolInstance
	}
	p.instances[i].Name = node
	return nil
}

func (p *fakePool) Remove(_ context.Context, id string) error {
	p.instances = slices.DeleteFunc(p.instances, func(in PoolInstance) bool { return in.ID == id })
	return nil
}

// fakeHosts lists every registered node; a node is live when its session is.
type fakeHosts struct {
	now       func() time.Time
	live      map[string]bool
	desired   []host.Desired
	cordoned  []string
	unretired []string
}

func (h *fakeHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	var hosts []host.HostStatus
	for node, live := range h.live {
		status := host.HostStatus{Registration: host.Registration{Node: node}}
		if live {
			status.SessionExpiresAt = h.now().Add(time.Hour)
		}
		hosts = append(hosts, status)
	}
	slices.SortFunc(hosts, func(a, b host.HostStatus) int {
		return strings.Compare(a.Registration.Node, b.Registration.Node)
	})
	return hosts, nil
}

func (h *fakeHosts) ListDesired(_ context.Context, role string) ([]host.Desired, error) {
	var out []host.Desired
	for _, d := range h.desired {
		if role == "" || d.Role == role {
			out = append(out, d)
		}
	}
	return out, nil
}

func (h *fakeHosts) Cordon(_ context.Context, node string) error {
	h.cordoned = append(h.cordoned, node)
	return nil
}

func (h *fakeHosts) Unretire(_ context.Context, node string) error {
	h.unretired = append(h.unretired, node)
	return nil
}

type fakeLeader struct{ snapshot authority.Snapshot }

func (f *fakeLeader) Current() authority.Snapshot { return f.snapshot }

func (f *fakeLeader) Guard(context.Context, uint64) error { return nil }

// fakeStore keeps the record encoded, as JetStream does, so one tick never shares memory with the next.
type fakeStore struct {
	data     []byte
	revision uint64
}

func (f *fakeStore) Load(context.Context) (Record, uint64, error) {
	if f.revision == 0 {
		return Record{}, 0, nil
	}
	var record Record
	err := protocol.DecodeStrict(f.data, &record, 0)
	return record, f.revision, err
}

func (f *fakeStore) Save(_ context.Context, record Record, revision uint64) (uint64, error) {
	if revision != f.revision {
		return 0, ErrRecordChanged
	}
	data, err := protocol.EncodeJSON(record)
	if err != nil {
		return 0, err
	}
	f.data = data
	f.revision++
	return f.revision, nil
}

// rig is one region's scaler on in-memory fakes. Its clock moves only when a test steps it.
type rig struct {
	t         *testing.T
	now       time.Time
	pool      *fakePool
	hosts     *fakeHosts
	cpu       map[string]float64 // latest CPU per node that reports a load
	backends  map[string]int
	revoked   []string
	journal   []decisionlog.Decision
	leader    *fakeLeader
	store     *fakeStore
	allowance int
	fresh     bool
	scaler    *Scaler
}

// newRig starts a region with three quorum nodes at 10% CPU, led by this process.
func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, now: t0, cpu: map[string]float64{}, backends: map[string]int{}, allowance: MaxNodes, fresh: true,
		leader: &fakeLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Ready: true, Leader: true,
			Epoch: 7, Revision: 3, ExpiresAt: time.Now().Add(time.Hour)}},
		store: &fakeStore{}}
	r.pool = &fakePool{now: func() time.Time { return r.now }}
	r.hosts = &fakeHosts{now: func() time.Time { return r.now }, live: map[string]bool{}}
	for _, node := range []string{"ts-gru-1", "ts-gru-2", "ts-gru-3"} {
		r.join(node, 0.1)
	}
	r.scaler = r.newScaler()
	return r
}

// newScaler is a leader with no history, on the region's shared store and pool.
func (r *rig) newScaler() *Scaler {
	return &Scaler{
		Cell:      "gru",
		Pool:      r.pool,
		Recipe:    func(context.Context) (Recipe, error) { return Recipe{Cell: "gru"}, nil },
		Hosts:     r.hosts,
		Loads:     r.loads,
		Allowance: func(time.Time) (int, bool) { return r.allowance, r.fresh },
		Revoke: func(_ context.Context, instanceID string) error {
			r.revoked = append(r.revoked, instanceID)
			return nil
		},
		Backends: func(_ context.Context, node, _ string) (int, error) { return r.backends[node], nil },
		Journal:  func(_ context.Context, decision decisionlog.Decision) { r.journal = append(r.journal, decision) },
		Leader:   r.leader,
		Store:    r.store,
		Now:      func() time.Time { return r.now },
	}
}

func (r *rig) loads() []NodeLoad {
	var loads []NodeLoad
	for node, cpu := range r.cpu {
		loads = append(loads, NodeLoad{Node: node, At: r.now, CPU: cpu, Memory: cpu, Disk: 0.1, Cores: 4})
	}
	return loads
}

// join gives node a live host session and a fresh load at cpu.
func (r *rig) join(node string, cpu float64) {
	r.hosts.live[node] = true
	r.cpu[node] = cpu
}

// quorum sets the CPU of the three quorum nodes.
func (r *rig) quorum(cpu float64) {
	for _, node := range []string{"ts-gru-1", "ts-gru-2", "ts-gru-3"} {
		r.cpu[node] = cpu
	}
}

// seedPoolNode adds a running, enrolled pool instance named node, created an hour before the test.
func (r *rig) seedPoolNode(node string, cpu float64) {
	r.pool.exists = true
	r.pool.instances = append(r.pool.instances, PoolInstance{ID: "ocid-" + node, Name: node, State: "RUNNING",
		PrivateIP: fmt.Sprintf("10.0.0.%d", nodeNumber(node)), Created: r.now.Add(-time.Hour)})
	r.join(node, cpu)
}

// tick runs one leader tick at the current time.
func (r *rig) tick() {
	r.t.Helper()
	if err := r.scaler.Tick(context.Background()); err != nil {
		r.t.Fatalf("tick at %s: %v", r.now.Format(time.TimeOnly), err)
	}
}

// step moves the clock one Interval on and ticks.
func (r *rig) step() {
	r.now = r.now.Add(Interval)
	r.tick()
}

// run steps every Interval until d has passed.
func (r *rig) run(d time.Duration) {
	for end := r.now.Add(d); r.now.Before(end); {
		r.step()
	}
}

// runUntil steps until done reports true, and fails after an hour of steps.
func (r *rig) runUntil(done func() bool) {
	r.t.Helper()
	for range 120 {
		r.step()
		if done() {
			return
		}
	}
	r.t.Fatalf("condition not reached within an hour, at %s", r.now.Format(time.TimeOnly))
}

// stored is the record the region last saved.
func (r *rig) stored() Record {
	r.t.Helper()
	record, _, err := r.store.Load(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return record
}

// entries returns the journal entries of kind.
func (r *rig) entries(kind decisionlog.Kind) []decisionlog.Decision {
	var out []decisionlog.Decision
	for _, entry := range r.journal {
		if entry.Kind == kind {
			out = append(out, entry)
		}
	}
	return out
}

// reasonCount counts the journal entries whose reason is reason.
func (r *rig) reasonCount(reason string) int {
	n := 0
	for _, entry := range r.journal {
		if entry.Reason == reason {
			n++
		}
	}
	return n
}

func instanceNames(instances []PoolInstance) []string {
	names := make([]string, 0, len(instances))
	for _, in := range instances {
		names = append(names, in.Name)
	}
	return names
}

func TestFollowerDoesNothing(t *testing.T) {
	r := newRig(t)
	r.leader.snapshot.Leader = false
	r.quorum(0.9)
	r.tick()
	r.run(10 * time.Minute)
	if len(r.pool.instances) != 0 || r.store.revision != 0 || len(r.journal) != 0 {
		t.Fatalf("follower acted: %d instances, revision %d, %d journal entries",
			len(r.pool.instances), r.store.revision, len(r.journal))
	}
}

func TestNamingPicksLowestFreeNode(t *testing.T) {
	t.Run("host registrations hold their names", func(t *testing.T) {
		r := newRig(t)
		r.hosts.live["ts-gru-4"] = false
		r.pool.exists = true
		r.pool.instances = []PoolInstance{
			{ID: "ocid-a", Name: "inst-a", State: "RUNNING", PrivateIP: "10.0.9.1"},
			{ID: "ocid-b", Name: "inst-b", State: "RUNNING", PrivateIP: "10.0.9.2"},
		}
		r.tick()
		if got := instanceNames(r.pool.instances); !slices.Equal(got, []string{"ts-gru-5", "ts-gru-6"}) {
			t.Fatalf("names = %v, want ts-gru-5 and ts-gru-6", got)
		}
		want := map[string]string{"ts-gru-5": "10.0.9.1", "ts-gru-6": "10.0.9.2"}
		if got := r.scaler.Addresses(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("addresses = %v, want %v", got, want)
		}
	})
	t.Run("pool instances hold their names", func(t *testing.T) {
		r := newRig(t)
		r.seedPoolNode("ts-gru-4", 0.1)
		r.pool.instances = append(r.pool.instances, PoolInstance{ID: "ocid-c", Name: "inst-c", State: "RUNNING"})
		r.tick()
		if got := instanceNames(r.pool.instances); !slices.Equal(got, []string{"ts-gru-4", "ts-gru-5"}) {
			t.Fatalf("names = %v, want ts-gru-4 and ts-gru-5", got)
		}
	})
}

func TestScaleUpFullCycle(t *testing.T) {
	r := newRig(t)
	r.quorum(0.9)
	r.tick()
	r.runUntil(func() bool { return r.stored().Action != nil })
	if up := r.stored().Action; up.Kind != Up || up.Step != stepGrow {
		t.Fatalf("action = %s at %s, want up at grow", up.Kind, up.Step)
	}
	if got := r.entries(decisionlog.KindScaleUp); len(got) != 1 || got[0].Summary != "scale gru from 3 to 4 nodes" {
		t.Fatalf("scale_up entries = %+v", got)
	}

	r.step() // grow: the pool holds one unnamed instance
	if r.stored().Action.Step != stepEnroll || len(r.pool.instances) != 1 {
		t.Fatalf("after grow: step %s, %d instances", r.stored().Action.Step, len(r.pool.instances))
	}

	r.step() // the instance is named, and enroll waits for its host session
	if got := instanceNames(r.pool.instances); !slices.Equal(got, []string{"ts-gru-4"}) {
		t.Fatalf("names = %v, want ts-gru-4", got)
	}
	if got := r.scaler.Addresses()["ts-gru-4"]; got != "10.0.9.1" {
		t.Fatalf("address of ts-gru-4 = %q", got)
	}
	if r.stored().Action == nil {
		t.Fatal("enroll finished before the node had a host session")
	}

	r.join("ts-gru-4", 0.9)
	r.step()
	if r.stored().Action != nil {
		t.Fatal("enroll did not finish once the node had a host session")
	}
	if got := r.entries(decisionlog.KindHostLaunched); len(got) != 1 || got[0].Attrs["nodes"] != "ts-gru-4" {
		t.Fatalf("host_launched entries = %+v", got)
	}
	if err := r.scaler.Status().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchTimeoutRemovesUnenrolledNode(t *testing.T) {
	r := newRig(t)
	r.quorum(0.9)
	r.tick()
	r.runUntil(func() bool { return r.stored().Action != nil })
	started := r.stored().LastChange
	r.quorum(0.3) // no second scale-up while the first one runs or cools down
	r.runUntil(func() bool { return r.stored().Action == nil })

	if len(r.pool.instances) != 0 {
		t.Fatalf("instances after expiry = %v, want none", instanceNames(r.pool.instances))
	}
	var expired []decisionlog.Decision
	for _, entry := range r.entries(decisionlog.KindHeld) {
		if entry.Rule == "nodescale.launch-expired" {
			expired = append(expired, entry)
		}
	}
	if len(expired) != 1 || expired[0].Reason != "no host session within 20m0s" {
		t.Fatalf("launch-expired entries = %+v", expired)
	}
	if got := r.stored().LastChange; !got.Equal(started) {
		t.Fatalf("LastChange = %s, want %s from the failed launch", got, started)
	}
}

func TestScaleDownFullCycle(t *testing.T) {
	r := newRig(t)
	r.seedPoolNode("ts-gru-4", 0.1)
	r.backends["ts-gru-4"] = 1
	r.hosts.desired = []host.Desired{{Cell: "gru", Node: "ts-gru-4", Role: "app"}}
	r.tick()
	r.runUntil(func() bool { return r.stored().Action != nil })
	if down := r.stored().Action; down.Kind != Down || down.Step != stepCordon || down.Node != "ts-gru-4" ||
		down.InstanceID != "ocid-ts-gru-4" {
		t.Fatalf("action = %+v, want down at cordon on ts-gru-4", down)
	}

	r.step() // cordon
	if !slices.Equal(r.hosts.cordoned, []string{"ts-gru-4"}) || r.stored().Action.Step != stepDrain {
		t.Fatalf("after cordon: cordoned %v, step %s", r.hosts.cordoned, r.stored().Action.Step)
	}
	r.run(5 * time.Minute) // a replica and a backend remain
	if r.stored().Action.Step != stepDrain {
		t.Fatalf("drain finished with a replica desired and a backend left: step %s", r.stored().Action.Step)
	}
	r.hosts.desired[0].Withdrawn = true
	r.run(5 * time.Minute)
	if r.stored().Action.Step != stepDrain {
		t.Fatalf("drain finished with a backend left: step %s", r.stored().Action.Step)
	}

	r.backends["ts-gru-4"] = 0
	r.step() // drained
	if r.stored().Action.Step != stepRemove {
		t.Fatalf("step = %s, want remove", r.stored().Action.Step)
	}
	r.step() // removed; OCI no longer lists the instance
	if r.stored().Action.Step != stepGone || len(r.pool.instances) != 0 {
		t.Fatalf("after remove: step %s, %d instances", r.stored().Action.Step, len(r.pool.instances))
	}
	r.step() // gone
	if r.stored().Action != nil || !slices.Equal(r.revoked, []string{"ocid-ts-gru-4"}) {
		t.Fatalf("after gone: action %+v, revoked %v", r.stored().Action, r.revoked)
	}
	if got := r.entries(decisionlog.KindScaleDown); len(got) != 1 || got[0].Summary != "scale gru from 4 to 3 nodes" {
		t.Fatalf("scale_down entries = %+v", got)
	}
	if got := r.entries(decisionlog.KindHostReclaimed); len(got) != 1 || got[0].Attrs["node"] != "ts-gru-4" {
		t.Fatalf("host_reclaimed entries = %+v", got)
	}
}

func TestDrainTimeoutUnretires(t *testing.T) {
	r := newRig(t)
	r.seedPoolNode("ts-gru-4", 0.1)
	r.hosts.desired = []host.Desired{{Cell: "gru", Node: "ts-gru-4", Role: "app"}}
	r.tick()
	r.runUntil(func() bool { return r.stored().Action != nil })
	r.step() // cordon
	r.runUntil(func() bool { return r.stored().Action == nil })

	if !slices.Equal(r.hosts.unretired, []string{"ts-gru-4"}) {
		t.Fatalf("unretired = %v, want ts-gru-4", r.hosts.unretired)
	}
	if got := r.reasonCount("drain did not finish within 30m0s"); got != 1 {
		t.Fatalf("drain timeout journaled %d times, want once", got)
	}
	if got := r.stored().LastChange; !got.Equal(r.now) {
		t.Fatalf("LastChange = %s, want the timeout at %s", got, r.now)
	}
	r.run(5 * time.Minute)
	if r.stored().Action != nil {
		t.Fatal("a second scale-down started inside the cooldown after a failed drain")
	}
}

func TestPoolNodeWithTerraBaseIsNeverPicked(t *testing.T) {
	r := newRig(t)
	r.seedPoolNode("ts-gru-4", 0.0) // the least loaded, but it holds a TerraBase member
	r.seedPoolNode("ts-gru-5", 0.2)
	r.hosts.desired = []host.Desired{{Cell: "gru", Node: "ts-gru-4", Role: "terrabase"}}
	r.tick()
	r.runUntil(func() bool { return r.stored().Action != nil })
	if got := r.stored().Action.Node; got != "ts-gru-5" {
		t.Fatalf("drain target = %s, want ts-gru-5", got)
	}
}

func TestDrainHoldJournaledOnce(t *testing.T) {
	r := newRig(t)
	r.seedPoolNode("ts-gru-4", 0.0)
	r.hosts.desired = []host.Desired{{Cell: "gru", Node: "ts-gru-4", Role: "terrabase"}}
	r.tick()
	r.run(31 * time.Minute)

	const reason = "no pool node is free to drain: each holds a terrabase member or lacks a load"
	if r.stored().Action != nil || len(r.hosts.cordoned) != 0 {
		t.Fatalf("drained a TerraBase node: action %+v, cordoned %v", r.stored().Action, r.hosts.cordoned)
	}
	if got := r.reasonCount(reason); got != 1 {
		t.Fatalf("hold %q journaled %d times, want once", reason, got)
	}
}

func TestNoGrowthWithoutFreshAllowance(t *testing.T) {
	r := newRig(t)
	r.allowance, r.fresh = MaxNodes, false // a stale allowance is not an allowance
	r.quorum(0.9)
	r.tick()
	r.run(10 * time.Minute)

	status := r.scaler.Status()
	if status.Action != Hold || status.Want != 4 || status.AllowanceFresh || status.Allowance != 3 {
		t.Fatalf("status = %+v, want a held want of 4 with allowance 3, not fresh", status)
	}
	if r.stored().Action != nil || len(r.pool.instances) != 0 {
		t.Fatal("grew without a fresh allowance")
	}
	if got := r.reasonCount("the budget allows 3 nodes"); got != 1 {
		t.Fatalf("budget hold journaled %d times, want once", got)
	}
}

func TestNewLeaderResumesAction(t *testing.T) {
	r := newRig(t)
	r.seedPoolNode("ts-gru-4", 0.1)
	started := r.now.Add(-5 * time.Minute)
	record := Record{LastChange: started, Action: &InFlight{ID: entityid.New(), Kind: Down, Step: stepDrain,
		Node: "ts-gru-4", InstanceID: "ocid-ts-gru-4", Started: started}}
	if _, err := r.store.Save(context.Background(), record, 0); err != nil {
		t.Fatal(err)
	}
	r.scaler = r.newScaler()
	r.runUntil(func() bool { return r.stored().Action == nil })

	if len(r.hosts.cordoned) != 0 {
		t.Fatalf("new leader cordoned again: %v", r.hosts.cordoned)
	}
	if !slices.Equal(r.revoked, []string{"ocid-ts-gru-4"}) {
		t.Fatalf("revoked = %v, want the resumed instance", r.revoked)
	}
}

func TestCostFillsTheStatusAndFailureLeavesSpendUnknown(t *testing.T) {
	r := newRig(t)
	r.scaler.Cost = func(context.Context, PoolState) (Cost, error) {
		return Cost{NodeMonthlyCents: 4100, ProjectedCents: 21000, Currency: "BRL", At: r.now}, nil
	}
	r.tick()
	status := r.scaler.Status()
	if status.NodeMonthlyCents != 4100 || status.ProjectedCents != 21000 || status.Currency != "BRL" || !status.CostAt.Equal(r.now) {
		t.Fatalf("status cost = %+v", status)
	}
	r.scaler.Cost = func(context.Context, PoolState) (Cost, error) {
		return Cost{NodeMonthlyCents: 4100, Currency: "BRL", At: r.now}, errors.New("cost report is stale")
	}
	r.step()
	if status := r.scaler.Status(); status.NodeMonthlyCents != 0 || status.Currency != "" || !status.CostAt.IsZero() {
		t.Fatalf("failed cost = %+v, want unknown spend", status)
	}
	r.scaler.Cost = func(context.Context, PoolState) (Cost, error) { return Cost{Currency: "real"}, nil }
	r.step()
	if status := r.scaler.Status(); status.Currency != "" || !status.CostAt.IsZero() {
		t.Fatalf("invalid currency cost = %+v, want unknown spend", status)
	}
}

func TestStatusValidate(t *testing.T) {
	valid := Status{Schema: StatusSchema, Cell: "gru", At: t0, Nodes: 4, QuorumNodes: 3, PoolNodes: 1,
		Want: 4, Allowance: 4, AllowanceFresh: true, Action: Hold, Reason: "load within band"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	withCost := valid
	withCost.Currency = "BRL"
	if err := withCost.Validate(); err != nil {
		t.Fatalf("status with an ISO currency: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Status)
	}{
		{"schema", func(s *Status) { s.Schema = 2 }},
		{"cell", func(s *Status) { s.Cell = "GRU" }},
		{"time", func(s *Status) { s.At = time.Time{} }},
		{"too many nodes", func(s *Status) { s.Nodes = MaxNodes + MaxPoolNodes + 1 }},
		{"negative pool", func(s *Status) { s.PoolNodes = -1 }},
		{"empty reason", func(s *Status) { s.Reason = "" }},
		{"long reason", func(s *Status) { s.Reason = strings.Repeat("r", maxReasonBytes+1) }},
		{"lower case currency", func(s *Status) { s.Currency = "brl" }},
		{"long currency", func(s *Status) { s.Currency = "BRLX" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := valid
			tc.edit(&status)
			if status.Validate() == nil {
				t.Fatalf("status with bad %s validated", tc.name)
			}
		})
	}
}
