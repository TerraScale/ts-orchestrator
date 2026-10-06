package cellscale

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Replay only db-1's readiness while every other member produces live reports.
type replayedReadiness struct {
	*fakeCell
	cached NodePressure
}

func (s replayedReadiness) Pressure(ctx context.Context, node string) (NodePressure, error) {
	if node == s.cached.Node {
		return s.cached, nil
	}
	return s.fakeCell.Pressure(ctx, node)
}

func TestAcceptedPressureMustNotRegress(t *testing.T) {
	cell := newFakeCell(3, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	p, err := cell.Pressure(t.Context(), "gru-1-db-1")
	if err != nil {
		t.Fatal(err)
	}
	s.controller.trackPressureIdentities(cell.instances)
	s.controller.pendingRestarts[NodeIdentity{Name: p.Node, InstanceID: p.InstanceID}] = restartFence{
		shape: small, process: "before-restart", after: s.now.Add(-time.Second),
	}
	if !s.controller.pressureUsable(p.Node, p) {
		t.Fatal("post-restart setup rejected")
	}
	newer := p
	s.now = s.now.Add(time.Second)
	newer.SampledAt, newer.State = s.now, StateJoining
	if !s.controller.pressureUsable(p.Node, newer) {
		t.Fatal("newer negative evidence rejected")
	}
	if s.controller.pressureUsable(p.Node, p) {
		t.Fatalf("ready report %s (%s) accepted after newer joining evidence %s (%s)",
			p.SampledAt, p.ProcessID, newer.SampledAt, newer.ProcessID)
	}
}

func TestConflictingPressureNeedsNewerEvidence(t *testing.T) {
	cell := newFakeCell(3, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	s.controller.trackPressureIdentities(cell.instances)
	ready, err := cell.Pressure(t.Context(), "gru-1-db-1")
	if err != nil || !s.controller.pressureUsable(ready.Node, ready) {
		t.Fatalf("initial ready sample: %v", err)
	}
	joining := ready
	joining.State = StateJoining
	if s.controller.pressureUsable(joining.Node, joining) {
		t.Fatal("conflicting state at the same timestamp was accepted")
	}
	for range 3 {
		if s.controller.pressureUsable(ready.Node, ready) || s.controller.pressureUsable(joining.Node, joining) {
			t.Fatal("replay resolved contradictory telemetry without a newer sample")
		}
	}
	s.now = s.now.Add(time.Second)
	joining.SampledAt = s.now
	if !s.controller.pressureUsable(joining.Node, joining) {
		t.Fatal("strictly newer unready evidence was refused")
	}
	if s.controller.pressureUsable(ready.Node, ready) {
		t.Fatal("older readiness replaced the new unready state")
	}
	s.now = s.now.Add(time.Second)
	ready.SampledAt = s.now
	if !s.controller.pressureUsable(ready.Node, ready) {
		t.Fatal("strictly newer readiness did not recover")
	}
}

func TestReplayedReadinessCannotOverlapRestarts(t *testing.T) {
	captureJournal(t)
	policy := testPolicy()
	policy.SustainUpSeconds, policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0, 0
	cell := newFakeCell(3, small, 2, 150)
	s := newSim(t, policy, cell, time.Minute)
	s.controller.config.ReadyTimeout = waitTimeout
	observed := observeState(t, policy, cell)
	// Complete a real first restart, then make the next recheck fail.
	s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
		_, _, pending := s.controller.restartFor(p.Node)
		if p.Node == "gru-1-db-1" && p.ProcessID != observed.Nodes[0].Pressure.ProcessID && p.State == StateReady && !pending {
			cell.unread["gru-1-db-3"] = true
		}
	}}
	big := Shape{OCPUs: 4, MemoryGB: 24}
	if err := s.controller.rollingResize(t.Context(), observed, big); err == nil || !strings.Contains(err.Error(), "gru-1-db-3 is not ready") {
		t.Fatalf("first restart setup: %v", err)
	}
	ready := s.controller.lastPressure[s.controller.activeIdentities["gru-1-db-1"]]
	_, _, pending := s.controller.restartFor(ready.Node)
	if ready.ProcessID == "" || ready.ProcessID == observed.Nodes[0].Pressure.ProcessID || ready.State != StateReady || pending ||
		!ready.SampledAt.After(s.controller.pressureAfter[ready.Node]) || len(cell.callLog()) != 1 {
		t.Fatalf("setup did not complete first restart: %+v", ready)
	}
	cell.unread["gru-1-db-3"] = false
	// A second process starts on db-1. Observe it joining during a rollout hold.
	s.now = s.now.Add(time.Second)
	cell.state["gru-1-db-1"] = StateJoining
	cell.process["gru-1-db-1"]++
	s.controller.config.Rollouts = func(context.Context) (bool, error) { return true, nil }
	if action, err := s.controller.Tick(t.Context()); err != nil || action.Reason != ReasonRollout {
		t.Fatalf("newer joining observation: action=%+v err=%v", action, err)
	}
	assertIdentityInvalidated(t, s.controller, ready.Identity())
	// All cached evidence is still within the two-minute freshness bound.
	s.controller.config.Rollouts = func(context.Context) (bool, error) { return false, nil }
	s.controller.config.Source = replayedReadiness{fakeCell: cell, cached: ready}
	snapshot := *observed.Replicas
	cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
	overlap := false
	cell.onResize = func(node string) {
		cell.state[node] = StateJoining
		down := 0
		for _, state := range cell.state {
			if state != StateReady {
				down++
			}
		}
		overlap = down > 1
	}
	action, err := s.controller.Tick(t.Context())
	if overlap || len(cell.callLog()) > 1 {
		t.Fatalf("replayed readiness authorized another restart with db-1 still joining: action=%s err=%v states=%v calls=%v",
			action.Kind, err, cell.state, cell.callLog())
	}
}
