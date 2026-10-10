package hostpool

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

var (
	now       = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	replica   = placement.Resources{CPU: 2, MemoryBytes: 4 << 30, DiskBytes: 10 << 30}
	testShape = placement.Resources{CPU: 4, MemoryBytes: 10 << 30, DiskBytes: 100 << 30}
)

func generalPool() NodePool {
	return NodePool{Name: "general", Environment: "prod", Roles: []string{"api"}, Shape: testShape,
		SystemReserveBytes: 2 << 30, FailureDomains: []string{"fd-1", "fd-2", "fd-3"}, Min: 1, Max: 4,
		IdleCooldownSeconds: 600, HostMonthlyCents: 100}
}

func apiDemand(replicas int, hosts ...placement.WorkloadHost) placement.WorkloadRequest {
	return placement.WorkloadRequest{Cell: "gru", Role: "api", Replicas: replicas, Request: replica, Hosts: hosts}
}

func TestNodePoolValidate(t *testing.T) {
	if err := generalPool().Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := map[string]func(*NodePool){
		"name":              func(p *NodePool) { p.Name = "General" },
		"hyphenated name":   func(p *NodePool) { p.Name = "gen-eral" },
		"long name":         func(p *NodePool) { p.Name = "thirteenchars" },
		"no roles":          func(p *NodePool) { p.Roles = nil },
		"zero shape":        func(p *NodePool) { p.Shape.CPU = 0 },
		"reserve too large": func(p *NodePool) { p.SystemReserveBytes = p.Shape.MemoryBytes },
		"no domains":        func(p *NodePool) { p.FailureDomains = nil },
		"repeated domain":   func(p *NodePool) { p.FailureDomains = []string{"fd-1", "fd-1"} },
		"inverted bounds":   func(p *NodePool) { p.Min = 5 },
		"short cooldown":    func(p *NodePool) { p.IdleCooldownSeconds = 1 },
	}
	for name, mutate := range invalid {
		pool := generalPool()
		mutate(&pool)
		if err := pool.Validate(); !errors.Is(err, ErrInvalidPool) {
			t.Errorf("%s: Validate() = %v", name, err)
		}
	}
	if err := ValidatePools([]NodePool{generalPool(), generalPool()}); !errors.Is(err, ErrInvalidPool) {
		t.Fatalf("repeated pool accepted: %v", err)
	}
}

// Pool hosts are cell servers: gru-1-pool-general-1 is ordinal 0 in gru.
func TestNodePoolOrdinal(t *testing.T) {
	pool := generalPool()
	for node, want := range map[string]int{"gru-1-pool-general-1": 0, "gru-1-pool-general-13": 12,
		"gru-1-pool-general-256": 255} {
		if got, ok := pool.Ordinal("gru", node); !ok || got != want || pool.NodeName("gru", want) != node {
			t.Errorf("Ordinal(%q) = %d, %v; NodeName = %q", node, got, ok, pool.NodeName("gru", want))
		}
	}
	for _, node := range []string{"general-1", "gru-1-pool-general", "gru-1-pool-general-0", "gru-1-pool-general-01",
		"gru-1-pool-general-x", "gru-1-pool-other-1", "gru-1-pool-general-257", "sfo-1-pool-general-1", "gru-1-db-1"} {
		if _, ok := pool.Ordinal("gru", node); ok {
			t.Errorf("Ordinal(%q) accepted", node)
		}
	}
	if _, ok := pool.Ordinal("lab", "lab-1-pool-general-1"); ok {
		t.Error("a cell outside the catalog has pool host names")
	}
}

func TestPlanPoolTable(t *testing.T) {
	member := func(ordinal int, domain string, allocations int) Member {
		return Member{Node: generalPool().NodeName("gru", ordinal), FailureDomain: domain, Allocations: allocations}
	}
	full := generalPool().virtualHost("gru", "gru-1-pool-general-1", "fd-1")
	full.Allocated = full.Capacity
	tests := []struct {
		name      string
		pool      func(*NodePool)
		members   []Member
		demands   []placement.WorkloadRequest
		idleSince map[string]time.Time
		want      Plan
	}{
		{
			name: "below min launches to min",
			want: Plan{Launch: []Launch{{Node: "gru-1-pool-general-1", FailureDomain: "fd-1"}}, Reason: "below-min"},
		},
		{
			name:    "demand launches fewest hosts across domains",
			members: []Member{member(0, "fd-1", 2)},
			demands: []placement.WorkloadRequest{apiDemand(2, full)},
			want: Plan{Launch: []Launch{{Node: "gru-1-pool-general-2", FailureDomain: "fd-2"}, {Node: "gru-1-pool-general-3", FailureDomain: "fd-3"}},
				Reason: "insufficient-capacity"},
		},
		{
			name:    "launching host already covers demand",
			members: []Member{member(0, "fd-1", 2), {Node: "gru-1-pool-general-2", FailureDomain: "fd-2", Launching: true}},
			demands: []placement.WorkloadRequest{apiDemand(1, full)},
			want:    Plan{Reason: "insufficient-capacity"},
		},
		{
			name:    "system reserve is not schedulable",
			members: []Member{member(0, "fd-1", 2)},
			demands: []placement.WorkloadRequest{{Cell: "gru", Role: "api", Replicas: 1, Hosts: []placement.WorkloadHost{full},
				Request: placement.Resources{CPU: 1, MemoryBytes: 9 << 30, DiskBytes: 1}}},
			want: Plan{Launch: []Launch{{Node: "gru-1-pool-general-2", FailureDomain: "fd-2"}, {Node: "gru-1-pool-general-3", FailureDomain: "fd-3"},
				{Node: "gru-1-pool-general-4", FailureDomain: "fd-1"}}, Reason: "pool-max-insufficient"},
		},
		{
			name:    "unsatisfiable demand launches to max",
			members: []Member{member(0, "fd-1", 2)},
			demands: []placement.WorkloadRequest{apiDemand(9, full)},
			want: Plan{Launch: []Launch{{Node: "gru-1-pool-general-2", FailureDomain: "fd-2"}, {Node: "gru-1-pool-general-3", FailureDomain: "fd-3"},
				{Node: "gru-1-pool-general-4", FailureDomain: "fd-1"}}, Reason: "pool-max-insufficient"},
		},
		{
			name:    "demand for another role is ignored",
			members: []Member{member(0, "fd-1", 1)},
			demands: []placement.WorkloadRequest{{Cell: "gru", Role: "worker", Replicas: 3, Request: replica}},
			want:    Plan{Reason: "at-min"},
		},
		{
			name:      "idle host before cooldown is kept",
			members:   []Member{member(0, "fd-1", 1), member(1, "fd-2", 0)},
			idleSince: map[string]time.Time{"gru-1-pool-general-2": now.Add(-5 * time.Minute)},
			want:      Plan{Reason: "no-idle-host"},
		},
		{
			name:    "highest idle ordinal is reclaimed after cooldown",
			members: []Member{member(0, "fd-1", 0), member(1, "fd-2", 0), member(2, "fd-3", 0)},
			idleSince: map[string]time.Time{"gru-1-pool-general-1": now.Add(-time.Hour), "gru-1-pool-general-2": now.Add(-time.Hour),
				"gru-1-pool-general-3": now.Add(-time.Hour)},
			want: Plan{Reclaim: []string{"gru-1-pool-general-3"}, Reason: "idle-cooldown-elapsed"},
		},
		{
			name:      "never reclaims below min",
			pool:      func(p *NodePool) { p.Min = 2 },
			members:   []Member{member(0, "fd-1", 0), member(1, "fd-2", 0)},
			idleSince: map[string]time.Time{"gru-1-pool-general-1": now.Add(-time.Hour), "gru-1-pool-general-2": now.Add(-time.Hour)},
			want:      Plan{Reason: "at-min"},
		},
		{
			name:      "pending demand blocks reclaim",
			members:   []Member{member(0, "fd-1", 0), member(1, "fd-2", 0)},
			demands:   []placement.WorkloadRequest{apiDemand(1, generalPool().virtualHost("gru", "gru-1-pool-general-1", "fd-1"))},
			idleSince: map[string]time.Time{"gru-1-pool-general-2": now.Add(-time.Hour)},
			want:      Plan{Reason: "insufficient-capacity"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := generalPool()
			if test.pool != nil {
				test.pool(&pool)
			}
			plan, err := PlanPool(PlanInput{Cell: "gru", Pool: pool, Members: test.members, Demands: test.demands,
				IdleSince: test.idleSince, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(plan, test.want) {
				t.Fatalf("plan = %#v, want %#v", plan, test.want)
			}
		})
	}
	if _, err := PlanPool(PlanInput{Pool: generalPool(), Members: []Member{{Node: "tb-1"}}, Now: now}); !errors.Is(err, ErrInvalidPool) {
		t.Fatalf("foreign member accepted: %v", err)
	}
}

type fakeView struct {
	hosts   []host.HostStatus
	desired []host.Desired
}

func (v *fakeView) ListHosts(context.Context) ([]host.HostStatus, error) { return v.hosts, nil }
func (v *fakeView) ListDesired(context.Context, string) ([]host.Desired, error) {
	return v.desired, nil
}

type fencer struct{ leader bool }

func (f fencer) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: f.leader, Ready: true, Epoch: 3, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}
func (fencer) Guard(context.Context, uint64) error { return nil }

// provisioner is OCI for the scaler: the hosts it holds, which launches add
// and reclaims remove. clock, when set, dates launches.
type provisioner struct {
	mu       sync.Mutex
	launched []string
	reclaims []string
	hosts    map[string]Instance
	clock    *time.Time
	// The fake is also the host retirer: busy nodes got an allocation.
	busy      map[string]bool
	retired   []string
	unretired []string
	// reclaimErr fails every reclaim, as an uncertain OCI termination.
	reclaimErr error
}

func (p *provisioner) Instances(context.Context) ([]Instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	instances := make([]Instance, 0, len(p.hosts))
	for _, instance := range p.hosts {
		instances = append(instances, instance)
	}
	return instances, nil
}

func (p *provisioner) Launch(_ context.Context, epoch uint64, pool NodePool, launch Launch) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if epoch != 3 {
		return errors.New("wrong epoch")
	}
	p.launched = append(p.launched, launch.Node)
	created := now
	if p.clock != nil {
		created = *p.clock
	}
	p.put(Instance{Node: launch.Node, Pool: pool.Name, Created: created})
	return nil
}

func (p *provisioner) Reclaim(_ context.Context, _ uint64, _ NodePool, node string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reclaimErr != nil {
		return p.reclaimErr
	}
	p.reclaims = append(p.reclaims, node)
	delete(p.hosts, node)
	return nil
}

// RetireIdle retires node unless busy names it; retired records it.
func (p *provisioner) RetireIdle(_ context.Context, node string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.busy[node] {
		return false, nil
	}
	p.retired = append(p.retired, node)
	return true, nil
}

func (p *provisioner) Unretire(_ context.Context, node string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unretired = append(p.unretired, node)
	return nil
}

// hold makes OCI hold already launched hosts of pool.
func (p *provisioner) hold(pool NodePool, nodes ...string) *provisioner {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, node := range nodes {
		p.put(Instance{Node: node, Pool: pool.Name, Created: now.Add(-30 * 24 * time.Hour)})
	}
	return p
}

func (p *provisioner) put(instance Instance) {
	if p.hosts == nil {
		p.hosts = make(map[string]Instance)
	}
	p.hosts[instance.Node] = instance
}

// openBudget is a budget no test plan reaches; with a provisioner the
// scaler launches only under one.
func openBudget() *Budget { return &Budget{MonthlyCapCents: MaxMonthlyCents, Currency: "USD"} }

// registered is a verified registration whose host holds a live session.
func registered(node, domain string, mutate ...func(*host.Registration)) host.HostStatus {
	r := host.Registration{Cell: "gru", Node: node, FailureDomain: domain, Environment: "prod", Roles: []string{"api"}}
	for _, change := range mutate {
		change(&r)
	}
	return host.HostStatus{Registration: r, Verified: true, SessionExpiresAt: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func TestScalerLaunchesOnceForDemandAndReclaimsIdleHosts(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1")},
		desired: []host.Desired{{Cell: "gru", Node: "gru-1-pool-general-1", Role: "api"}}}
	clock := now
	prov := (&provisioner{clock: &clock}).hold(generalPool(), "gru-1-pool-general-1")
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: view, Fencer: fencer{leader: true},
		Provisioner: prov, Retirer: prov, Budget: openBudget, Spend: &fakeSpend{}, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	full := generalPool().virtualHost("gru", "gru-1-pool-general-1", "fd-1")
	full.Allocated = full.Capacity
	scaler.RequestCapacity(workload.ServiceSpec{Role: "api", Environment: "prod"}, apiDemand(1, full))
	for range 2 {
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(prov.launched, []string{"gru-1-pool-general-2"}) {
		t.Fatalf("launched = %v", prov.launched)
	}
	// The launched host registers and the demand ages out; general-1 stays
	// idle past its cooldown and is reclaimed exactly once.
	view.hosts = append(view.hosts, registered("gru-1-pool-general-2", "fd-2"))
	clock = clock.Add(DefaultDemandTTL + time.Second)
	if err := scaler.Tick(context.Background()); err != nil || len(prov.reclaims) != 0 {
		t.Fatalf("reclaimed before cooldown: %v (%v)", prov.reclaims, err)
	}
	clock = clock.Add(11 * time.Minute)
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prov.reclaims, []string{"gru-1-pool-general-2"}) {
		t.Fatalf("reclaims = %v, last = %#v", prov.reclaims, scaler.Last())
	}
}

func TestScalerRecommendOnlyFollowerAndDedicatedHosts(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1", func(r *host.Registration) {
		r.ManagedMember = &host.ManagedMemberBinding{HostAttempt: 1}
	})}}
	follower, _ := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: view, Fencer: fencer{},
		Provisioner: &provisioner{}, Retirer: &provisioner{}, Now: func() time.Time { return now }})
	if err := follower.Tick(context.Background()); err != nil || len(follower.Last()) != 0 {
		t.Fatalf("follower planned: %v (%v)", follower.Last(), err)
	}
	recommend, _ := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: view, Fencer: fencer{leader: true},
		Now: func() time.Time { return now }})
	err := recommend.Tick(context.Background())
	if err == nil {
		t.Fatal("dedicated host with a pool name was accepted as a member")
	}
	if plan := recommend.Last()["general"]; len(plan.Launch) != 1 || plan.Reason != "below-min" ||
		plan.Launch[0].Node == "gru-1-pool-general-1" {
		t.Fatalf("plan = %#v", plan)
	}
}

func newTestScaler(t *testing.T, view *fakeView, pool NodePool, clock *time.Time, prov *provisioner) *Scaler {
	t.Helper()
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{pool}, Hosts: view, Fencer: fencer{leader: true},
		Provisioner: prov, Retirer: prov, Budget: openBudget, Spend: &fakeSpend{}, Now: func() time.Time { return *clock }})
	if err != nil {
		t.Fatal(err)
	}
	return scaler
}

// In-flight launches keep their failure domain, so a second batch spreads to
// the least-used domain instead of repeating the first one.
func TestScalerSpreadsLaunchesAcrossDomainsWhileLaunching(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1")},
		desired: []host.Desired{{Cell: "gru", Node: "gru-1-pool-general-1", Role: "api"}}}
	clock := now
	prov := (&provisioner{clock: &clock}).hold(generalPool(), "gru-1-pool-general-1")
	scaler := newTestScaler(t, view, generalPool(), &clock, prov)
	full := generalPool().virtualHost("gru", "gru-1-pool-general-1", "fd-1")
	full.Allocated = full.Capacity
	spec := workload.ServiceSpec{Role: "api", Environment: "prod"}
	scaler.RequestCapacity(spec, apiDemand(1, full))
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Demand grows while general-1 (fd-2) is still launching; replicas of
	// one role never share a host, so the second replica needs a launch.
	scaler.RequestCapacity(spec, apiDemand(2, full))
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if plan := scaler.Last()["general"]; len(plan.Launch) != 1 || plan.Launch[0].FailureDomain != "fd-3" {
		t.Fatalf("second launch = %+v, want one host in fd-3", plan)
	}
}

// A registered member the recorded demand predates still counts as capacity,
// and a satisfied service clears its demand.
func TestScalerCountsMembersNewerThanDemandAndClearsSatisfiedDemand(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1")},
		desired: []host.Desired{{Cell: "gru", Node: "gru-1-pool-general-1", Role: "api"}}}
	clock := now
	prov := (&provisioner{clock: &clock}).hold(generalPool(), "gru-1-pool-general-1")
	scaler := newTestScaler(t, view, generalPool(), &clock, prov)
	full := generalPool().virtualHost("gru", "gru-1-pool-general-1", "fd-1")
	full.Allocated = full.Capacity
	spec := workload.ServiceSpec{Role: "api", Environment: "prod"}
	scaler.RequestCapacity(spec, apiDemand(1, full))
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	view.hosts = append(view.hosts, registered("gru-1-pool-general-2", "fd-2"))
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prov.launched, []string{"gru-1-pool-general-2"}) {
		t.Fatalf("launched = %v: the registered host was not counted for the stale demand", prov.launched)
	}
	scaler.CapacitySatisfied(spec)
	scaler.mu.Lock()
	remaining := len(scaler.demands)
	scaler.mu.Unlock()
	if remaining != 0 {
		t.Fatal("a satisfied service kept its capacity demand")
	}
}

// A dedicated or foreign host holding a pool name reserves that ordinal.
func TestPlanPoolNeverLaunchesReservedOrdinals(t *testing.T) {
	plan, err := PlanPool(PlanInput{Cell: "gru", Pool: generalPool(), Now: now, ReservedOrdinals: []int{0}})
	if err != nil || len(plan.Launch) != 1 || plan.Launch[0].Node != "gru-1-pool-general-2" {
		t.Fatalf("plan = %+v (%v), want general-1", plan, err)
	}
}

// A host that disappears without a reclaim forgets its idle time, so a
// same-named host that registers later gets a full cooldown.
func TestScalerForgetsIdleTimeOfVanishedHosts(t *testing.T) {
	both := []host.HostStatus{registered("gru-1-pool-general-1", "fd-1"), registered("gru-1-pool-general-2", "fd-2")}
	view := &fakeView{hosts: both, desired: []host.Desired{{Cell: "gru", Node: "gru-1-pool-general-1", Role: "api"}}}
	clock := now
	prov := (&provisioner{clock: &clock}).hold(generalPool(), "gru-1-pool-general-1", "gru-1-pool-general-2")
	scaler := newTestScaler(t, view, generalPool(), &clock, prov)
	steps := []struct {
		after time.Duration
		hosts []host.HostStatus
		held  []string
	}{
		{0, both, []string{"gru-1-pool-general-1", "gru-1-pool-general-2"}},
		{5 * time.Minute, both[:1], []string{"gru-1-pool-general-1"}},
		{6 * time.Minute, both, []string{"gru-1-pool-general-1", "gru-1-pool-general-2"}},
	}
	for _, step := range steps {
		clock = clock.Add(step.after)
		view.hosts = step.hosts
		prov.hosts = nil
		prov.hold(generalPool(), step.held...)
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(prov.reclaims) != 0 {
		t.Fatalf("re-registered host reclaimed without a fresh cooldown: %v", prov.reclaims)
	}
}

// Each demand's snapshot excludes its own replicas. A retained replica of
// one role must still be charged when a later role is simulated.
func TestPlanPoolChargesRetainedReplicasAcrossRoles(t *testing.T) {
	pool := generalPool()
	pool.Roles = []string{"api", "web"}
	pool.Shape = placement.Resources{CPU: replica.CPU, MemoryBytes: replica.MemoryBytes + pool.SystemReserveBytes,
		DiskBytes: replica.DiskBytes}
	busy := func(allocated placement.Resources) placement.WorkloadHost {
		existing := pool.virtualHost("gru", "gru-1-pool-general-1", "fd-1")
		existing.Allocated = allocated
		return existing
	}
	api := placement.WorkloadRequest{Cell: "gru", Role: "api", Replicas: 2, Request: replica,
		Hosts:    []placement.WorkloadHost{busy(placement.Resources{})},
		Previous: []placement.Assignment{{Node: "gru-1-pool-general-1", Role: "api", Ready: true}}}
	web := placement.WorkloadRequest{Cell: "gru", Role: "web", Replicas: 1, Request: replica,
		Hosts: []placement.WorkloadHost{busy(replica)}}
	plan, err := PlanPool(PlanInput{Cell: "gru", Pool: pool, Now: now,
		Members: []Member{{Node: "gru-1-pool-general-1", FailureDomain: "fd-1", Allocations: 1}},
		Demands: []placement.WorkloadRequest{api, web}})
	if err != nil || len(plan.Launch) != 2 {
		t.Fatalf("plan = %+v (%v), want two single-replica hosts", plan, err)
	}
}

// A demand that only fails its per-domain cap still grows the pool into a
// domain with room.
func TestPlanPoolHonoursDomainCapOfDemand(t *testing.T) {
	pool := generalPool()
	free := func(node string) placement.WorkloadHost { return pool.virtualHost("gru", node, "fd-1") }
	demand := apiDemand(2, free("gru-1-pool-general-1"), free("gru-1-pool-general-2"))
	demand.MaxPerFailureDomain = 1
	plan, err := PlanPool(PlanInput{Cell: "gru", Pool: pool, Now: now,
		Members: []Member{{Node: "gru-1-pool-general-1", FailureDomain: "fd-1"}, {Node: "gru-1-pool-general-2", FailureDomain: "fd-1"}},
		Demands: []placement.WorkloadRequest{demand}})
	if err != nil || len(plan.Launch) != 1 || plan.Launch[0].FailureDomain == "fd-1" {
		t.Fatalf("plan = %+v (%v), want one launch outside fd-1", plan, err)
	}
}

// With a provisioner, OCI says which pool hosts exist. A registration whose
// host is gone is stale and frees its name; a silent host and a terminating
// one keep their names but are not capacity.
func TestScalerTrustsOCIOverRegistrations(t *testing.T) {
	silent := registered("gru-1-pool-general-2", "fd-2")
	silent.SessionExpiresAt = now.Add(-time.Minute)
	silentFirst := registered("gru-1-pool-general-1", "fd-1")
	silentFirst.SessionExpiresAt = now.Add(-time.Minute)
	for name, test := range map[string]struct {
		hosts    []host.HostStatus
		held     []Instance
		launched string
	}{
		"stale registration": {hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1")},
			launched: "gru-1-pool-general-1"},
		"silent host": {hosts: []host.HostStatus{silent},
			held: []Instance{{Node: "gru-1-pool-general-2", Pool: "general", Created: now.Add(-time.Hour)}}, launched: "gru-1-pool-general-1"},
		"silent first host": {hosts: []host.HostStatus{silentFirst},
			held:     []Instance{{Node: "gru-1-pool-general-1", Pool: "general", Created: now.Add(-time.Hour)}},
			launched: "gru-1-pool-general-2"},
		"terminating host": {hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1")},
			held:     []Instance{{Node: "gru-1-pool-general-1", Pool: "general", Created: now.Add(-time.Hour), Terminating: true}},
			launched: "gru-1-pool-general-2"},
	} {
		clock := now
		prov := &provisioner{clock: &clock}
		for _, instance := range test.held {
			prov.put(instance)
		}
		scaler := newTestScaler(t, &fakeView{hosts: test.hosts}, generalPool(), &clock, prov)
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(prov.launched, []string{test.launched}) || len(prov.reclaims) != 0 {
			t.Errorf("%s: launched %v, reclaimed %v", name, prov.launched, prov.reclaims)
		}
	}
}

// A pool host that never gets a live session within the launch grace is
// terminated, also one a former leader launched, so it costs nothing and
// its name is free again.
func TestScalerReclaimsHostsThatNeverCameUp(t *testing.T) {
	recorder := &captureRecorder{}
	t.Cleanup(decisionlog.SetDefault(recorder))
	pool := generalPool()
	pool.Min = 0
	clock := now
	prov := &provisioner{clock: &clock}
	prov.put(Instance{Node: "gru-1-pool-general-1", Pool: "general", Created: now.Add(-DefaultLaunchGrace - time.Minute)})
	prov.put(Instance{Node: "gru-1-pool-general-2", Pool: "general", Created: now.Add(-time.Minute)})
	scaler := newTestScaler(t, &fakeView{}, pool, &clock, prov)
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prov.reclaims, []string{"gru-1-pool-general-1"}) {
		t.Fatalf("reclaimed %v", prov.reclaims)
	}
	clock = clock.Add(DefaultLaunchGrace)
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prov.reclaims, []string{"gru-1-pool-general-1", "gru-1-pool-general-2"}) || len(prov.launched) != 0 {
		t.Fatalf("reclaimed %v, launched %v", prov.reclaims, prov.launched)
	}
	var expired int
	for _, decision := range recorder.decisions {
		if decision.Kind == decisionlog.KindHostReclaimed && decision.Rule == "hostpool."+reasonLaunchExpired {
			expired++
		}
	}
	if expired != 2 {
		t.Fatalf("journaled %d expired reclaims: %+v", expired, recorder.decisions)
	}
}

// A provisioner launches only under a cell budget; a cell outside the
// catalog has no names for pool hosts at all.
func TestScalerNeedsABudgetAndServerNames(t *testing.T) {
	prov := &provisioner{}
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: &fakeView{},
		Fencer: fencer{leader: true}, Provisioner: prov, Retirer: prov, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := scaler.Last()["general"]; len(prov.launched) != 0 || last.Hold != reasonBudgetMissing || last.Withheld != 1 {
		t.Fatalf("launched %v without a budget, plan %+v", prov.launched, last)
	}
	if _, err := NewScaler(Config{Cell: "lab", Pools: []NodePool{generalPool()}, Hosts: &fakeView{},
		Fencer: fencer{leader: true}}); err == nil {
		t.Fatal("a cell outside the catalog got a pool scaler")
	}
}

// A host OCI gives no creation time, or one in the future, gets the whole
// launch grace from when the scaler first saw it, and the budget charges it.
func TestScalerDatesHostsWithoutAUsableCreationTimeFromFirstSight(t *testing.T) {
	pool := generalPool()
	pool.Min = 0
	clock := now
	prov := &provisioner{clock: &clock}
	prov.put(Instance{Node: "gru-1-pool-general-1", Pool: "general"})
	prov.put(Instance{Node: "gru-1-pool-general-2", Pool: "general", Created: now.Add(365 * 24 * time.Hour)})
	scaler := newTestScaler(t, &fakeView{}, pool, &clock, prov)
	for _, step := range []time.Duration{0, DefaultLaunchGrace} {
		clock = clock.Add(step)
		if err := scaler.Tick(context.Background()); err != nil || len(prov.reclaims) != 0 {
			t.Fatalf("after %s: reclaimed %v, %v", clock.Sub(now), prov.reclaims, err)
		}
	}
	clock = clock.Add(time.Second)
	if err := scaler.Tick(context.Background()); err != nil || len(prov.reclaims) != 2 {
		t.Fatalf("after the grace: reclaimed %v, %v", prov.reclaims, err)
	}
	gate := scaler.budgetGate(context.Background(), clock, []Instance{{Node: "gru-1-pool-general-3", Pool: "general"}})
	if gate.hold != "" || gate.headroom != int64(MaxMonthlyCents-generalPool().HostMonthlyCents) {
		t.Fatalf("a host without a creation time was not charged: %+v", gate)
	}
}

// A reclaim retires the host first; a host that got an allocation since the
// tick began is kept, and a launch frees a retired host's name.
func TestScalerKeepsAHostThatGotAnAllocation(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1"),
		registered("gru-1-pool-general-2", "fd-2")}}
	clock := now
	prov := (&provisioner{clock: &clock, busy: map[string]bool{"gru-1-pool-general-2": true}}).hold(generalPool(),
		"gru-1-pool-general-1", "gru-1-pool-general-2")
	scaler := newTestScaler(t, view, generalPool(), &clock, prov)
	for _, step := range []time.Duration{0, 11 * time.Minute} {
		clock = clock.Add(step)
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(prov.reclaims) != 0 || !slices.Equal(prov.retired, nil) {
		t.Fatalf("reclaimed %v, retired %v", prov.reclaims, prov.retired)
	}
	pool := generalPool()
	pool.Min = 2
	view.hosts = nil
	prov.hosts = nil
	refill := newTestScaler(t, view, pool, &clock, prov)
	if err := refill.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prov.launched, []string{"gru-1-pool-general-1", "gru-1-pool-general-2"}) ||
		!slices.Equal(prov.unretired, prov.launched) {
		t.Fatalf("launched %v, unretired %v", prov.launched, prov.unretired)
	}
}

// A termination whose outcome is unknown leaves the host retired: OCI may
// be deleting it, so no allocation may land on it.
func TestScalerKeepsAHostRetiredWhenItsTerminationFails(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1"),
		registered("gru-1-pool-general-2", "fd-2")}}
	clock := now
	prov := (&provisioner{clock: &clock, reclaimErr: errors.New("connection reset")}).hold(generalPool(),
		"gru-1-pool-general-1", "gru-1-pool-general-2")
	scaler := newTestScaler(t, view, generalPool(), &clock, prov)
	for _, step := range []time.Duration{0, 11 * time.Minute} {
		clock = clock.Add(step)
		_ = scaler.Tick(context.Background())
	}
	if !slices.Equal(prov.retired, []string{"gru-1-pool-general-2"}) || len(prov.unretired) != 0 {
		t.Fatalf("retired %v, unretired %v", prov.retired, prov.unretired)
	}
}
