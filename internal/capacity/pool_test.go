package capacity

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
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
		IdleCooldownSeconds: 600}
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

func TestNodePoolOrdinal(t *testing.T) {
	pool := generalPool()
	for node, want := range map[string]int{"general-0": 0, "general-12": 12} {
		if got, ok := pool.Ordinal(node); !ok || got != want {
			t.Errorf("Ordinal(%q) = %d, %v", node, got, ok)
		}
	}
	for _, node := range []string{"general", "general-", "general-01", "general-x", "other-1", "general-1000"} {
		if _, ok := pool.Ordinal(node); ok {
			t.Errorf("Ordinal(%q) accepted", node)
		}
	}
}

func TestPlanPoolTable(t *testing.T) {
	member := func(ordinal int, domain string, allocations int) Member {
		return Member{Node: generalPool().NodeName(ordinal), FailureDomain: domain, Allocations: allocations}
	}
	full := generalPool().virtualHost("gru", "general-0", "fd-1")
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
			want: Plan{Launch: []Launch{{Node: "general-0", FailureDomain: "fd-1"}}, Reason: "below-min"},
		},
		{
			name:    "demand launches fewest hosts across domains",
			members: []Member{member(0, "fd-1", 2)},
			demands: []placement.WorkloadRequest{apiDemand(2, full)},
			want: Plan{Launch: []Launch{{Node: "general-1", FailureDomain: "fd-2"}, {Node: "general-2", FailureDomain: "fd-3"}},
				Reason: "insufficient-capacity"},
		},
		{
			name:    "launching host already covers demand",
			members: []Member{member(0, "fd-1", 2), {Node: "general-1", FailureDomain: "fd-2", Launching: true}},
			demands: []placement.WorkloadRequest{apiDemand(1, full)},
			want:    Plan{Reason: "insufficient-capacity"},
		},
		{
			name:    "system reserve is not schedulable",
			members: []Member{member(0, "fd-1", 2)},
			demands: []placement.WorkloadRequest{{Cell: "gru", Role: "api", Replicas: 1, Hosts: []placement.WorkloadHost{full},
				Request: placement.Resources{CPU: 1, MemoryBytes: 9 << 30, DiskBytes: 1}}},
			want: Plan{Launch: []Launch{{Node: "general-1", FailureDomain: "fd-2"}, {Node: "general-2", FailureDomain: "fd-3"},
				{Node: "general-3", FailureDomain: "fd-1"}}, Reason: "pool-max-insufficient"},
		},
		{
			name:    "unsatisfiable demand launches to max",
			members: []Member{member(0, "fd-1", 2)},
			demands: []placement.WorkloadRequest{apiDemand(9, full)},
			want: Plan{Launch: []Launch{{Node: "general-1", FailureDomain: "fd-2"}, {Node: "general-2", FailureDomain: "fd-3"},
				{Node: "general-3", FailureDomain: "fd-1"}}, Reason: "pool-max-insufficient"},
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
			idleSince: map[string]time.Time{"general-1": now.Add(-5 * time.Minute)},
			want:      Plan{Reason: "no-idle-host"},
		},
		{
			name:    "highest idle ordinal is reclaimed after cooldown",
			members: []Member{member(0, "fd-1", 0), member(1, "fd-2", 0), member(2, "fd-3", 0)},
			idleSince: map[string]time.Time{"general-0": now.Add(-time.Hour), "general-1": now.Add(-time.Hour),
				"general-2": now.Add(-time.Hour)},
			want: Plan{Reclaim: []string{"general-2"}, Reason: "idle-cooldown-elapsed"},
		},
		{
			name:      "never reclaims below min",
			pool:      func(p *NodePool) { p.Min = 2 },
			members:   []Member{member(0, "fd-1", 0), member(1, "fd-2", 0)},
			idleSince: map[string]time.Time{"general-0": now.Add(-time.Hour), "general-1": now.Add(-time.Hour)},
			want:      Plan{Reason: "at-min"},
		},
		{
			name:      "pending demand blocks reclaim",
			members:   []Member{member(0, "fd-1", 0), member(1, "fd-2", 0)},
			demands:   []placement.WorkloadRequest{apiDemand(1, generalPool().virtualHost("gru", "general-0", "fd-1"))},
			idleSince: map[string]time.Time{"general-1": now.Add(-time.Hour)},
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
	return authority.Snapshot{Leader: f.leader, Ready: true, Epoch: 3, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}
func (fencer) Guard(context.Context, uint64) error { return nil }

type provisioner struct {
	mu       sync.Mutex
	launched []string
	reclaims []string
}

func (p *provisioner) Launch(_ context.Context, epoch uint64, _ NodePool, launch Launch) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if epoch != 3 {
		return errors.New("wrong epoch")
	}
	p.launched = append(p.launched, launch.Node)
	return nil
}

func (p *provisioner) Reclaim(_ context.Context, _ uint64, _ NodePool, node string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reclaims = append(p.reclaims, node)
	return nil
}

func registered(node, domain string, mutate ...func(*host.Registration)) host.HostStatus {
	r := host.Registration{Cell: "gru", Node: node, FailureDomain: domain, Environment: "prod", Roles: []string{"api"}}
	for _, change := range mutate {
		change(&r)
	}
	return host.HostStatus{Registration: r, Verified: true}
}

func TestScalerLaunchesOnceForDemandAndReclaimsIdleHosts(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("general-0", "fd-1")},
		desired: []host.Desired{{Cell: "gru", Node: "general-0", Role: "api"}}}
	clock := now
	prov := &provisioner{}
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: view, Fencer: fencer{leader: true},
		Provisioner: prov, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	full := generalPool().virtualHost("gru", "general-0", "fd-1")
	full.Allocated = full.Capacity
	scaler.RequestCapacity(workload.ServiceSpec{Role: "api", Environment: "prod"}, apiDemand(1, full))
	for range 2 {
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(prov.launched, []string{"general-1"}) {
		t.Fatalf("launched = %v", prov.launched)
	}
	// The launched host registers and the demand ages out; general-1 stays
	// idle past its cooldown and is reclaimed exactly once.
	view.hosts = append(view.hosts, registered("general-1", "fd-2"))
	clock = clock.Add(DefaultDemandTTL + time.Second)
	if err := scaler.Tick(context.Background()); err != nil || len(prov.reclaims) != 0 {
		t.Fatalf("reclaimed before cooldown: %v (%v)", prov.reclaims, err)
	}
	clock = clock.Add(11 * time.Minute)
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prov.reclaims, []string{"general-1"}) {
		t.Fatalf("reclaims = %v, last = %#v", prov.reclaims, scaler.Last())
	}
}

func TestScalerRecommendOnlyFollowerAndDedicatedHosts(t *testing.T) {
	view := &fakeView{hosts: []host.HostStatus{registered("general-0", "fd-1", func(r *host.Registration) {
		r.ManagedMember = &host.ManagedMemberBinding{HostAttempt: 1}
	})}}
	follower, _ := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: view, Fencer: fencer{},
		Provisioner: &provisioner{}, Now: func() time.Time { return now }})
	if err := follower.Tick(context.Background()); err != nil || len(follower.Last()) != 0 {
		t.Fatalf("follower planned: %v (%v)", follower.Last(), err)
	}
	recommend, _ := NewScaler(Config{Cell: "gru", Pools: []NodePool{generalPool()}, Hosts: view, Fencer: fencer{leader: true},
		Now: func() time.Time { return now }})
	err := recommend.Tick(context.Background())
	if err == nil {
		t.Fatal("dedicated host with a pool name was accepted as a member")
	}
	if plan := recommend.Last()["general"]; len(plan.Launch) != 1 || plan.Reason != "below-min" {
		t.Fatalf("plan = %#v", plan)
	}
}
