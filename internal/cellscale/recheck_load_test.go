package cellscale

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

type changedLoad struct {
	*fakeCell
	change func(*NodePressure)
}

func (s changedLoad) Pressure(ctx context.Context, node string) (NodePressure, error) {
	p, err := s.fakeCell.Pressure(ctx, node)
	s.change(&p)
	return p, err
}

func TestScaleInRechecksLoadBeforeDrain(t *testing.T) {
	policy := testPolicy()
	for _, test := range []struct {
		name string
		load func(*NodePressure)
	}{
		{"CPU", func(p *NodePressure) { p.CPUUtil = policy.Targets.CPUUtil / 2 }},
		{"memory", func(p *NodePressure) { p.MemoryUtil = policy.Targets.MemoryUtil / 2 }},
		{"disk", func(p *NodePressure) {
			p.DiskUsedBytes = int64(float64(p.DiskTotalBytes) * policy.Targets.DiskUtil / 2)
		}},
		{"IOPS", func(p *NodePressure) { p.DiskIOPS = policy.Targets.DiskIOPS / 2 }},
		{"requests", func(p *NodePressure) { p.RequestRate = policy.Targets.RequestRate / 2 }},
		{"queue", func(p *NodePressure) { p.IOQueueDepth = policy.Targets.IOQueueDepth / 2 }},
		{"latency", func(p *NodePressure) { p.P95LatencyMS = policy.Targets.P95LatencyMS / 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			state := observeState(t, policy, cell)
			action := act(policy, state, History{})
			if action.Kind != KindScaleIn || action.Reason != ReasonLowPressure {
				t.Fatalf("initial shrink = %+v", action)
			}
			s.controller.config.Source = changedLoad{fakeCell: cell, change: test.load}
			err := s.controller.apply(t.Context(), state, action)
			if err == nil || !strings.Contains(err.Error(), "projected pressure") || len(cell.callLog()) != 0 {
				t.Fatalf("drained after %s rose: %v, calls=%v", test.name, err, cell.callLog())
			}
		})
	}
}

func TestRebalanceRechecksTenantAndDestinationFit(t *testing.T) {
	for _, change := range []string{"none", "busy destination", "tenant grows", "tenant disappears", "destination CPU rises", "destination shape shrinks", "duplicate tenant", "zero demand", "wrong resource", "hotspot cleared"} {
		t.Run(change, func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(3, small, 4, 200)
			cell.tenants["gru-1-db-2"] = append(cell.tenants["gru-1-db-2"], TenantLoad{Project: project("noisy"), RequestRate: 1300})
			cell.tenants["gru-1-db-1"] = cell.tenants["gru-1-db-1"][:2]
			s := newSim(t, policy, cell, time.Minute)
			state := observeState(t, policy, cell)
			action := act(policy, state, History{})
			if action.Kind != KindRebalance || action.Tenant != project("noisy") || action.Target != "gru-1-db-1" {
				t.Fatalf("initial move = %+v", action)
			}
			switch change {
			case "zero demand", "wrong resource", "hotspot cleared":
				s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
					if p.Node != action.Node {
						return
					}
					if change == "hotspot cleared" {
						p.CPUUtil, p.RequestRate = 0.1, 200
					} else {
						for i := range p.TopTenants {
							if p.TopTenants[i].Project == action.Tenant {
								p.TopTenants[i].CPUShare, p.TopTenants[i].RequestRate = 0, 0
								if change == "wrong resource" {
									p.TopTenants[i].CPUShare = 0.3 // Only requests are hot.
								}
							}
						}
					}
				}}
			case "busy destination":
				for i := range cell.tenants[action.Target] {
					cell.tenants[action.Target][i].RequestRate = 900
				}
			case "tenant grows":
				cell.tenants[action.Node][4].RequestRate = 1800
			case "tenant disappears":
				cell.tenants[action.Node] = cell.tenants[action.Node][:4]
			case "destination CPU rises":
				s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
					if p.Node == action.Target {
						p.CPUUtil = 0.65
					}
				}}
			case "destination shape shrinks":
				cell.instances[0].Shape = Shape{OCPUs: 1, MemoryGB: 6}
			case "duplicate tenant":
				s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
					if p.Node == action.Node {
						p.TopTenants = []TenantLoad{
							{Project: action.Tenant, RequestRate: 10, CPUShare: 0.01},
							{Project: action.Tenant, RequestRate: 1800, CPUShare: 0.9},
						}
					}
				}}
			}
			err := s.controller.apply(t.Context(), state, action)
			if change == "none" {
				if err != nil || len(cell.callLog()) != 1 {
					t.Fatalf("safe move refused: %v, calls=%v", err, cell.callLog())
				}
			} else if err == nil || len(cell.callLog()) != 0 {
				t.Fatalf("unsafe move after %s: %v, calls=%v", change, err, cell.callLog())
			}
		})
	}
}

type rejectedResize struct {
	*fakeCell
	reject   bool
	attempts int
}

func (c *rejectedResize) Resize(ctx context.Context, id string, shape Shape) error {
	c.attempts++
	if c.reject {
		return ErrResizeRejected
	}
	return c.fakeCell.Resize(ctx, id, shape)
}

func TestRejectedResizeCanRetryPauseAndResume(t *testing.T) {
	audit := captureJournal(t)
	policy := testPolicy()
	policy.SustainUpSeconds, policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0, 0
	policy.MaxFailures = 2
	cell := newFakeCell(3, small, 2, 150)
	cell.coresPerRequest = 1.0 / 150
	s := newSim(t, policy, cell, time.Minute)
	cloud := &rejectedResize{fakeCell: cell, reject: true}
	s.controller.config.Cloud = cloud
	for attempt := 1; attempt <= policy.MaxFailures; attempt++ {
		action, err := s.controller.Tick(t.Context())
		if action.Kind != KindResize || !errors.Is(err, ErrResizeRejected) || len(cell.callLog()) != 0 {
			t.Fatalf("rejection cannot retry: %+v, %v, calls=%v", action, err, cell.callLog())
		}
		if cloud.attempts != attempt || len(s.controller.pendingRestarts) != 0 || s.controller.History().Failures != attempt {
			t.Fatalf("rejected resize retained an in-flight fence or retried within the tick: attempts=%d, pending=%v, history=%+v", cloud.attempts, s.controller.pendingRestarts, s.controller.History())
		}
		failed := 0
		for _, d := range audit.decisions {
			if d.Status == decisionlog.StatusFailed && d.Attrs["action"] == string(KindResize) && d.ParentID != "" {
				failed++
			}
		}
		if failed != attempt {
			t.Fatalf("rejected resize failed audit entries=%d, want %d", failed, attempt)
		}
	}
	if !s.controller.History().Paused || cloud.attempts != policy.MaxFailures {
		t.Fatalf("rejected attempts did not reach pause: %+v, attempts=%d", s.controller.History(), cloud.attempts)
	}
	cloud.reject = false
	s.controller.Resume()
	action, err := s.controller.Tick(t.Context())
	if err != nil || action.Kind != KindResize || len(cell.callLog()) != 3 {
		t.Fatalf("resumed resize did not recover: %+v, %v, calls=%v", action, err, cell.callLog())
	}
}

func TestShapeRefusalRequiresFreshPressureBeforeRetry(t *testing.T) {
	for _, mode := range []string{"stable", "fresh pressure", "cached pressure"} {
		t.Run(mode, func(t *testing.T) {
			captureJournal(t)
			policy := testPolicy()
			policy.SustainUpSeconds, policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0, 0
			policy.MonthlyBudget = policy.MonthlyCost(4, small) - 1 // Mixed-shape convergence is unaffordable.
			cell := newFakeCell(4, small, 10, 125)
			s := newSim(t, policy, cell, time.Minute)
			source, target := "gru-1-db-1", "gru-1-db-2"
			s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
				if p.Node == source {
					p.CPUUtil = 0.9
				}
			}}
			original := s.observe()
			cached := *original.Nodes[1].Pressure
			if mode == "cached pressure" {
				s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
					if p.Node == source {
						p.CPUUtil = 0.9
					}
					if p.Node == target {
						*p = cached
					}
				}}
			}
			action := Action{Kind: KindRebalance, Node: source, Target: target, Tenant: project("org-1-0")}
			if !moveFits(policy.Targets, original.Nodes[0], original.Nodes[1], original.Nodes[0].Pressure.TopTenants[0]) {
				t.Fatal("baseline move does not fit")
			}
			lists := 0
			s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
				lists++
				if mode != "stable" && lists == 3 {
					cell.instances[1].Shape.OCPUs = 1
				}
			}}
			firstErr := s.controller.apply(t.Context(), original, action)
			if mode == "stable" {
				if firstErr != nil || len(cell.callLog()) != 1 {
					t.Fatalf("stable move refused: %v calls=%v", firstErr, cell.callLog())
				}
				return
			}
			if lists != 3 || firstErr == nil || !strings.Contains(firstErr.Error(), "shape changed") || len(cell.callLog()) != 0 {
				t.Fatalf("initial mismatch not rejected: lists=%d err=%v calls=%v", lists, firstErr, cell.callLog())
			}
			s.controller.history = s.controller.history.Recorded(s.now, false, policy.MaxFailures)
			s.now = s.now.Add(10 * time.Second)
			retry, retryErr := s.controller.Tick(t.Context())
			if mode == "fresh pressure" {
				if retryErr != nil || retry.Kind != KindRebalance || retry.Target == target || len(cell.callLog()) != 1 {
					t.Fatalf("fresh pressure could not safely move to another peer: retry=%+v err=%v calls=%v", retry, retryErr, cell.callLog())
				}
				return
			}
			// Before the shrink the target used .3125 * 2 = .625 OCPU.
			// This tenant uses .9 * .1 * 2 = .18 OCPU, so the one-core
			// target would reach .805, above its .7 utilization target.
			actualProjected := (cached.CPUUtil*original.Nodes[1].Shape.OCPUs +
				original.Nodes[0].Pressure.CPUUtil*original.Nodes[0].Pressure.TopTenants[0].CPUShare*original.Nodes[0].Shape.OCPUs) / cell.instances[1].Shape.OCPUs
			if actualProjected <= policy.Targets.CPUUtil {
				t.Fatal("probe does not overload target")
			}
			if len(cell.callLog()) != 0 {
				t.Fatalf("shape refusal retained pre-shrink pressure: retry=%+v err=%v calls=%v cached_sample=%s pressure_floor=%s actual_projected_cpu=%g target_cpu=%g",
					retry, retryErr, cell.callLog(), cached.SampledAt, s.controller.pressureAfter[target], actualProjected, policy.Targets.CPUUtil)
			}
		})
	}
}

func TestShapeDiscoveryFencesPressureBeforeRPC(t *testing.T) {
	cell := newFakeCell(4, small, 10, 125)
	s := newSim(t, testPolicy(), cell, time.Minute)
	original := s.observe()
	s.now = s.now.Add(10 * time.Second)
	discovery := s.now
	cell.instances[1].Shape.OCPUs = 1
	cell.instances[2].Shape.MemoryGB = 6
	checked := false
	s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
		if !checked {
			for _, node := range original.Nodes[1:3] {
				_, cached := s.controller.lastPressure[node.Identity()]
				if cached || s.controller.lastReplicas != nil || !s.controller.pressureAfter[node.Name].Equal(discovery.Add(MaxPressureClockSkew)) {
					t.Fatalf("shape discovery did not fence every node before pressure RPC: %s", node.Name)
				}
			}
			checked = true
		}
		for _, node := range original.Nodes[1:3] {
			if p.Node == node.Name {
				*p = *node.Pressure
			}
		}
	}}
	state := s.observe()
	if !checked || state.Nodes[1].Pressure != nil || state.Nodes[2].Pressure != nil || len(cell.callLog()) != 0 {
		t.Fatalf("shape discovery accepted cached utilization: %+v calls=%v", state, cell.callLog())
	}
	s.now = s.now.Add(MaxPressureClockSkew + time.Second)
	s.controller.config.Source = cell
	recovered := s.observe()
	for i := 1; i <= 2; i++ {
		node := recovered.Nodes[i]
		if node.Pressure == nil || !node.Pressure.SampledAt.After(discovery.Add(MaxPressureClockSkew)) ||
			!s.controller.pressureAfter[node.Name].Equal(discovery.Add(MaxPressureClockSkew)) {
			t.Fatalf("fresh shape evidence failed to recover without refencing: %+v", node)
		}
	}
	if recovered.Nodes[1].Pressure.CPUUtil != original.Nodes[1].Pressure.CPUUtil*2 ||
		recovered.Nodes[2].Pressure.MemoryUtil != original.Nodes[2].Pressure.MemoryUtil*2 {
		t.Fatal("recovery did not measure utilization against the changed shapes")
	}
}
