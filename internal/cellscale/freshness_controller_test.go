package cellscale

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type cachedPressure struct {
	*fakeCell
	sampledAt time.Time
	state     NodeState
}

func (s cachedPressure) Pressure(ctx context.Context, node string) (NodePressure, error) {
	p, err := s.fakeCell.Pressure(ctx, node)
	p.SampledAt = s.sampledAt
	if s.state != "" {
		p.State = s.state
	}
	return p, err
}

func TestStalePressureBlocksShrinkAndItsRecheck(t *testing.T) {
	for _, kind := range []Kind{KindScaleIn, KindResize} {
		for _, sample := range []string{"unknown", "stale", "future"} {
			t.Run(string(kind)+"/"+sample, func(t *testing.T) {
				captureJournal(t)
				policy := testPolicy()
				policy.SustainDownSeconds = 0
				cell := newFakeCell(4, small, 2, 150)
				if kind == KindResize {
					cell = newFakeCell(3, Shape{OCPUs: 4, MemoryGB: 24}, 2, 150)
				}
				s := newSim(t, policy, cell, time.Minute)
				state := s.observe()
				action := act(policy, state, History{})
				if action.Kind != kind {
					t.Fatalf("fresh setup = %+v, want %s", action, kind)
				}
				stamp := time.Time{}
				if sample == "stale" {
					stamp = s.now.Add(-MaxPressureAge - time.Second)
				} else if sample == "future" {
					stamp = s.now.Add(MaxPressureClockSkew + time.Second)
				}
				s.controller.config.Source = cachedPressure{fakeCell: cell, sampledAt: stamp}
				if got, err := s.controller.Tick(t.Context()); err != nil || got.Kind != KindHold || got.Reason != ReasonNotSettled {
					t.Fatalf("cached pressure tick = %+v, %v", got, err)
				}
				if err := s.controller.apply(t.Context(), state, action); err == nil || !strings.Contains(err.Error(), "not ready") {
					t.Fatalf("cached pressure authorized shrink: %v", err)
				}
				if calls := cell.callLog(); len(calls) != 0 {
					t.Fatalf("cached pressure mutated the cell: %v", calls)
				}
			})
		}
	}
}

func TestCachedReadyAndDrainedReportsCannotFinishWaits(t *testing.T) {
	for _, state := range []NodeState{StateReady, StateDrained} {
		t.Run(string(state), func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			s.controller.config.ReadyTimeout = 20 * time.Millisecond
			expected := identities(s.observe().Nodes)
			cached := s.now.Add(-MaxPressureAge - time.Second)
			s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
				if p.Node == "gru-1-db-4" {
					p.State, p.SampledAt = state, cached
				}
			}}
			if err := s.controller.waitNode(t.Context(), expected, "gru-1-db-4", func(p NodePressure) bool { return p.State == state }); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cached %s report completed wait: %v", state, err)
			}
		})
	}
}
