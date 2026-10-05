package cellscale

import (
	"testing"
	"time"
)

func TestNextNodeNamingCapacity(t *testing.T) {
	state := State{Cell: "gru-1", Nodes: []Node{{Ordinal: 1}}}
	for ordinal := 2; ordinal <= maxOrdinal; ordinal++ {
		state.Reserved = append(state.Reserved, ordinal)
	}
	if got := nextNode(state); got != "" {
		t.Fatalf("all supported names occupied: nextNode = %q", got)
	}
	state.Reserved = state.Reserved[:len(state.Reserved)-1]
	if got := nextNode(state); got != NodeName(state.Cell, maxOrdinal) {
		t.Fatalf("last supported name free: nextNode = %q", got)
	}
	state.Reserved = state.Reserved[1:]
	if got := nextNode(state); got != "gru-1-db-2" {
		t.Fatalf("lowest name free: nextNode = %q", got)
	}
}

func TestNamingCapacityHoldsScaleOut(t *testing.T) {
	for _, test := range []struct {
		name    string
		nodes   int
		rate    float64
		hotspot bool
		reason  string
	}{
		{"below min", 2, 500, false, ReasonBelowMin},
		{"hot scale-out", 3, 1200, false, ReasonHighPressure + ":" + string(SignalRequestRate)},
		{"hotspot scale-out", 3, 500, true, ReasonHotspot},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			policy.SustainUpSeconds = 0
			cell := newFakeCell(test.nodes, small, 2, test.rate)
			if test.hotspot {
				for index := range cell.tenants["gru-1-db-1"] {
					cell.tenants["gru-1-db-1"][index].RequestRate = 1200
				}
			}
			if action := act(policy, observeState(t, policy, cell), History{}); action.Kind != KindScaleOut || action.Reason != test.reason {
				t.Fatalf("setup did not want the expected scale-out: %+v", action)
			}
			for ordinal := test.nodes + 1; ordinal <= maxOrdinal; ordinal++ {
				cell.instances = append(cell.instances, Instance{Name: NodeName(cell.cell, ordinal), State: "RUNNING", Foreign: true})
			}
			sim := newSim(t, policy, cell, time.Minute)
			for range policy.MaxFailures + 1 {
				action, err := sim.controller.Tick(t.Context())
				if err != nil || action.Kind != KindHold || action.Reason != ReasonAtCapacity {
					t.Fatalf("naming capacity exhausted: action=%+v, err=%v", action, err)
				}
				sim.now = sim.now.Add(time.Minute)
			}
			history := sim.controller.History()
			if len(cell.callLog()) != 0 || history.Failures != 0 || history.Paused || len(history.Actions) != 0 {
				t.Fatalf("capacity hold attempted an action: calls=%v, history=%+v", cell.callLog(), history)
			}
		})
	}
}
