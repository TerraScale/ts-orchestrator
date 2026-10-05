package cellscale

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestResizeDownChecksEveryNode(t *testing.T) {
	for _, test := range []struct {
		name   string
		cpu    [3]float64
		memory [3]float64
		want   Kind
	}{
		{"uneven CPU", [3]float64{0.9, 0.1, 0.1}, [3]float64{0.1, 0.1, 0.1}, KindHold},
		{"uneven memory", [3]float64{0.1, 0.1, 0.1}, [3]float64{0.9, 0.1, 0.1}, KindHold},
		{"within threshold", [3]float64{0.3, 0.1, 0.1}, [3]float64{0.3, 0.1, 0.1}, KindResize},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			policy.ScaleDownBelow = 0.8
			big := Shape{OCPUs: 4, MemoryGB: 24}
			state := observeState(t, policy, newFakeCell(3, big, 2, 150))
			for i, node := range state.Nodes {
				node.Pressure.CPUUtil = test.cpu[i] * policy.Targets.CPUUtil
				node.Pressure.MemoryUtil = test.memory[i] * policy.Targets.MemoryUtil
			}
			action := act(policy, state, History{})
			if action.Kind != test.want || action.Kind == KindResize && action.To != small {
				t.Fatalf("resize with skew = %+v, want %s", action, test.want)
			}
			// The rail also protects corrections and any caller that already
			// chose a resize, independently of the load-driven decision.
			action, _ = rails(policy, state, History{}, Action{Kind: KindResize, From: big, To: small}, policy.MonthlyCost(3, big))
			if action.Kind != test.want {
				t.Fatalf("resize rail with skew = %+v, want %s", action, test.want)
			}
		})
	}
}

func TestRollingResizePreservesTenantReplicaQuorum(t *testing.T) {
	for _, replicas := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprint(replicas), func(t *testing.T) {
			policy := testPolicy()
			policy.ReplicationFactor = replicas
			policy.Nodes.Min = max(3, replicas)
			cell := newFakeCell(4, small, 4, 250)
			s := newSim(t, policy, cell, time.Minute)
			state := observeState(t, policy, cell)
			big := Shape{OCPUs: 4, MemoryGB: 24}
			action, _ := rails(policy, state, History{}, Action{Kind: KindResize, From: small, To: big}, 0)
			err := s.controller.rollingResize(t.Context(), state, big)
			if replicas < 3 {
				if action.Kind != KindHold || action.Reason != ReasonQuorum || err == nil || len(cell.callLog()) != 0 {
					t.Fatalf("unsafe tenant restart: replicas=%d, rail=%+v, err=%v, calls=%v", replicas, action, err, cell.callLog())
				}
				cell.setScale(2.6)
				if got := act(policy, observeState(t, policy, cell), History{}); got.Kind != KindScaleOut {
					t.Fatalf("unsafe restart should use horizontal growth: %+v", got)
				}
			} else if action.Kind != KindResize || err != nil || len(cell.callLog()) != 4 {
				t.Fatalf("safe tenant restart blocked: replicas=%d, rail=%+v, err=%v, calls=%v", replicas, action, err, cell.callLog())
			}
		})
	}
}

func TestResizeDownRechecksPressureBeforeRestart(t *testing.T) {
	for _, resource := range []string{"CPU", "memory"} {
		t.Run(resource, func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(3, Shape{OCPUs: 4, MemoryGB: 24}, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			state := observeState(t, policy, cell)
			action := act(policy, state, History{})
			if action.Kind != KindResize || action.To != small {
				t.Fatalf("setup did not downsize: %+v", action)
			}
			if resource == "CPU" {
				for i := range cell.tenants["gru-1-db-1"] {
					cell.tenants["gru-1-db-1"][i].RequestRate = 1200
				}
			} else {
				cell.memoryGB = 20
			}
			err := s.controller.apply(t.Context(), state, action)
			if err == nil || !strings.Contains(err.Error(), "projected pressure") || len(cell.callLog()) != 0 {
				t.Fatalf("resized after load increased: %v, calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestScaleOutRechecksBeforeLaunch(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*fakeCell, *Controller)
		want   string
	}{
		{"rollout gate", func(_ *fakeCell, c *Controller) {
			c.config.Rollouts = func(context.Context) (bool, error) { return true, nil }
		}, "rollout is in flight"},
		{"release skew", func(f *fakeCell, _ *Controller) { f.release["gru-1-db-2"] = "r2" }, "rollout is in flight"},
		{"unready peer", func(f *fakeCell, _ *Controller) { f.state["gru-1-db-2"] = StateJoining }, "not ready"},
		{"unreadable peer", func(f *fakeCell, _ *Controller) { f.unread["gru-1-db-2"] = true }, "not ready"},
		{"lagging peer", func(f *fakeCell, _ *Controller) { f.lag = map[string]uint64{"gru-1-db-2": 5000} }, "events behind"},
		{"membership changed", func(f *fakeCell, _ *Controller) { f.instances = slices.Delete(f.instances, 1, 2) }, "membership changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(3, small, 4, 250)
			cell.setScale(2.6)
			s := newSim(t, policy, cell, time.Minute)
			state := s.observe()
			action := act(policy, state, History{})
			if action.Kind != KindScaleOut {
				t.Fatalf("setup did not scale out: %+v", action)
			}
			test.change(cell, s.controller)
			err := s.controller.apply(t.Context(), state, action)
			if err == nil || !strings.Contains(err.Error(), test.want) || len(cell.callLog()) != 0 {
				t.Fatalf("launched after cell changed: %v, calls=%v", err, cell.callLog())
			}
		})
	}
}
