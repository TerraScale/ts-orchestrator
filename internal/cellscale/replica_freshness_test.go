package cellscale

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Fresh placement is measured after the controller's convergence fence.
// Overrides still return their own timestamps, including deliberate caches.
type liveReplicaInventory struct {
	*fakeCell
	controller *Controller
}

func (m liveReplicaInventory) Replicas(ctx context.Context, node string) (ReplicaSnapshot, error) {
	if m.fakeCell.replicas == nil && !m.now().After(m.controller.replicasAfter) {
		after := m.controller.replicasAfter.Add(time.Second)
		if m.advance != nil {
			m.advance(after.Sub(m.now()))
		} else {
			m.fakeCell.now = func() time.Time { return after }
			m.controller.config.Now = m.fakeCell.now
		}
	}
	return m.fakeCell.Replicas(ctx, node)
}

func TestReplicaInventoryRequiresPostStartupEvidence(t *testing.T) {
	for _, kind := range []string{"drain", "restart", "drain recovery"} {
		for _, offset := range []time.Duration{-time.Second, 3 * time.Second, MaxPressureClockSkew} {
			t.Run(kind+"/"+offset.String(), func(t *testing.T) {
				policy := testPolicy()
				cell := newFakeCell(4, small, 2, 150)
				s := newSim(t, policy, cell, time.Minute)
				if kind == "drain recovery" {
					cell.state["gru-1-db-4"] = StateDrained
				}
				state := observeState(t, policy, cell)
				snapshot := safeReplicaSnapshot(s.now.Add(offset), cell)
				cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
				var err error
				s.controller, err = New(s.controller.config)
				if err != nil {
					t.Fatal(err)
				}
				s.now = s.now.Add(10 * time.Second)
				current, err := s.controller.observe(t.Context())
				if err != nil || current.Replicas != nil || slices.ContainsFunc(current.Nodes, func(n Node) bool { return n.Pressure == nil }) {
					t.Fatalf("pre-start placement passed fresh pressure: state=%+v err=%v", current, err)
				}
				action := Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: kind == "drain recovery"}
				if kind == "restart" {
					action = Action{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}}
				}
				if got, _ := rails(policy, current, History{}, action, 0); got.Kind != KindHold || got.Reason != ReasonQuorum {
					t.Fatalf("startup rail accepted cached placement: %+v", got)
				}
				if err := s.controller.apply(t.Context(), state, action); err == nil || len(cell.callLog()) != 0 {
					t.Fatalf("startup placement authorized effects: err=%v calls=%v", err, cell.callLog())
				}
				cell.replicas = nil
				s.controller.config.Members = liveReplicaInventory{cell, s.controller}
				s.now = s.now.Add(MaxPressureClockSkew + time.Second)
				want := 2 // Drain then terminate.
				if kind == "restart" {
					want = 4
				} else if kind == "drain recovery" {
					want = 1
				}
				if err := s.controller.apply(t.Context(), state, action); err != nil || len(cell.callLog()) != want {
					t.Fatalf("fresh post-start placement did not recover: err=%v calls=%v", err, cell.callLog())
				}
			})
		}
	}
}

func TestReplicaInventoryCannotRegressOrResolveConflictsByReplay(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	s.observe()
	s.now = s.now.Add(time.Second)
	initial := safeReplicaSnapshot(s.now, cell)
	if !s.controller.replicasUsable(initial) {
		t.Fatal("initial inventory rejected")
	}
	// Different wire ordering describes the same sets, not a conflict.
	reordered := safeReplicaSnapshot(s.now, cell)
	slices.Reverse(reordered.Members)
	slices.Reverse(reordered.Placements)
	slices.Reverse(reordered.Placements[0].LiveReplicas)
	if !s.controller.replicasUsable(reordered) {
		t.Fatal("placement ordering manufactured a contradiction")
	}
	s.now = s.now.Add(time.Second)
	newer := safeReplicaSnapshot(s.now, cell)
	newer.Placements[1].LiveReplicas = []string{"gru-1-db-2"}
	if !s.controller.replicasUsable(newer) || s.controller.replicasUsable(initial) {
		t.Fatal("older healthy placement replaced newer under-replicated evidence")
	}
	if !s.controller.lastReplicas.SampledAt.Equal(newer.SampledAt) || len(s.controller.lastReplicas.Placements[1].LiveReplicas) != 1 {
		t.Fatal("replay changed the accepted inventory")
	}
	accepted := *s.controller.lastReplicas
	invalid := safeReplicaSnapshot(s.now.Add(time.Second), cell)
	invalid.Complete = false
	if s.controller.replicasUsable(invalid) || !reflect.DeepEqual(accepted, *s.controller.lastReplicas) {
		t.Fatal("invalid inventory replaced the accepted sample")
	}
	conflict := safeReplicaSnapshot(s.now, cell)
	if s.controller.replicasUsable(conflict) {
		t.Fatal("equal-timestamp contradictory placement accepted")
	}
	for range 3 {
		if s.controller.replicasUsable(newer) || s.controller.replicasUsable(conflict) || s.controller.replicasUsable(initial) {
			t.Fatal("replay resolved contradictory inventory without a newer sample")
		}
	}
	s.now = s.now.Add(time.Second)
	if !s.controller.replicasUsable(safeReplicaSnapshot(s.now, cell)) || s.controller.replicasUsable(initial) {
		t.Fatal("strictly newer placement failed to recover monotonically")
	}
	if len(cell.callLog()) != 0 {
		t.Fatalf("inventory acceptance caused effects: %v", cell.callLog())
	}
}

func TestMembershipMismatchPreservesReplicaRefusalTimestamp(t *testing.T) {
	for _, evidence := range []string{"under-replicated", "contradictory"} {
		for _, offset := range []time.Duration{-2 * time.Second, 0, 2 * time.Second} {
			t.Run(evidence+"/"+offset.String(), func(t *testing.T) {
				cell := newFakeCell(4, small, 2, 150)
				s := newSim(t, testPolicy(), cell, time.Minute)
				state := s.observe()
				s.now = s.now.Add(3 * time.Second)
				under := safeReplicaSnapshot(s.now, cell)
				under.Placements[1].LiveReplicas = []string{"gru-1-db-2"}
				if !s.controller.replicasUsable(under) {
					t.Fatal("under-replicated evidence was not retained")
				}
				if evidence == "contradictory" && s.controller.replicasUsable(safeReplicaSnapshot(s.now, cell)) {
					t.Fatal("conflicting placement accepted")
				}
				mismatch := safeReplicaSnapshot(s.now.Add(offset), cell)
				mismatch.Members[0].Incarnation = "unobserved-process"
				floor := under.SampledAt
				if mismatch.SampledAt.After(floor) {
					floor = mismatch.SampledAt
				}
				if s.controller.replicasUsable(mismatch) || s.controller.lastReplicas != nil ||
					!s.controller.replicasAfter.Equal(floor) {
					t.Fatalf("mismatch discarded newer refusal evidence: floor=%s want=%s", s.controller.replicasAfter, floor)
				}
				for _, at := range []time.Time{under.SampledAt.Add(-time.Second), under.SampledAt, floor} {
					if s.controller.replicasUsable(safeReplicaSnapshot(at, cell)) {
						t.Fatalf("matching healthy inventory at %s bypassed refusal floor %s", at, floor)
					}
				}
				mismatch.SampledAt = under.SampledAt.Add(-3 * time.Second)
				if s.controller.replicasUsable(mismatch) || !s.controller.replicasAfter.Equal(floor) {
					t.Fatal("repeated old mismatch lowered the current refusal floor")
				}
				state.Now, state.Replicas = s.now, nil
				if removalSafe(testPolicy(), state, "gru-1-db-4") == nil ||
					replicasSafe(testPolicy(), state, "gru-1-db-1", testPolicy().quorum()) == nil {
					t.Fatal("replayed inventory authorized removal or restart")
				}
				s.now = floor.Add(time.Second)
				if !s.controller.replicasUsable(safeReplicaSnapshot(s.now, cell)) {
					t.Fatal("strictly newer matching inventory failed to recover")
				}
				state.Now, state.Replicas = s.now, s.controller.lastReplicas
				if removalSafe(testPolicy(), state, "gru-1-db-4") != nil ||
					replicasSafe(testPolicy(), state, "gru-1-db-1", testPolicy().quorum()) != nil || len(cell.callLog()) != 0 {
					t.Fatal("fresh safe evidence could not recover the gates without effects")
				}
			})
		}
	}
}

func TestReplicaFloorTracksUnreadyUnknownAndClockRegression(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	snapshot := safeReplicaSnapshot(s.now, cell)
	cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
	if _, err := s.controller.observe(t.Context()); err != nil {
		t.Fatal(err)
	}
	prior := s.controller.replicasAfter
	s.now = s.now.Add(time.Second)
	cell.state["gru-1-db-1"] = StateJoining
	if state, err := s.controller.observe(t.Context()); err != nil || state.Replicas != nil || !s.controller.replicasAfter.After(prior) {
		t.Fatalf("unready evidence failed to fence placement: state=%+v err=%v", state, err)
	}
	prior = s.controller.replicasAfter
	s.now = s.now.Add(time.Second)
	if _, err := s.controller.observe(t.Context()); err != nil || !s.controller.replicasAfter.Equal(prior) {
		t.Fatalf("unchanged recovery state moved the convergence floor: %v", err)
	}
	cell.state["gru-1-db-1"] = StateReady
	cell.process["gru-1-db-1"]++
	if state, err := s.controller.observe(t.Context()); err != nil || state.Replicas != nil || !s.controller.replicasAfter.After(prior) {
		t.Fatalf("recovered process reused pre-convergence placement: state=%+v err=%v", state, err)
	}
	prior = s.controller.replicasAfter
	s.now = s.now.Add(time.Second)
	cell.unread["gru-1-db-1"] = true
	if _, err := s.controller.observe(t.Context()); err != nil || !s.controller.replicasAfter.After(prior) {
		t.Fatalf("unknown node failed to fence placement: %v", err)
	}
	prior = s.controller.replicasAfter
	s.now = s.now.Add(-time.Second)
	s.controller.fenceReplicas()
	if !s.controller.replicasAfter.Equal(prior) {
		t.Fatal("controller clock regression lowered the inventory floor")
	}
	cell.unread["gru-1-db-1"] = false
	s.now = prior.Add(time.Second)
	snapshot = safeReplicaSnapshot(s.now, cell)
	if state, err := s.controller.observe(t.Context()); err != nil || state.Replicas == nil || len(cell.callLog()) != 0 {
		t.Fatalf("fresh convergence failed to recover without effects: state=%+v err=%v calls=%v", state, err, cell.callLog())
	}
}

func TestRollingResizeWaitsForPostConvergencePlacement(t *testing.T) {
	for _, mode := range []string{"before restart", "within convergence skew", "convergence boundary"} {
		t.Run(mode, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			s.observe()
			s.now = s.now.Add(time.Second)
			s.controller.config.ReadyTimeout = waitTimeout
			cached := safeReplicaSnapshot(s.now, cell)
			cell.replicas = func() (ReplicaSnapshot, error) {
				snapshot := cached
				if cell.process["gru-1-db-1"] > 1 {
					switch mode {
					case "within convergence skew":
						snapshot.SampledAt = s.now.Add(3 * time.Second)
					case "convergence boundary":
						snapshot.SampledAt = s.controller.replicasAfter
					}
				}
				return snapshot, nil
			}
			state := observeState(t, testPolicy(), cell)
			big := Shape{OCPUs: 4, MemoryGB: 24}
			err := s.controller.rollingResize(t.Context(), state, big)
			ready := s.controller.lastPressure[s.controller.activeIdentities["gru-1-db-1"]]
			if !errors.Is(err, context.DeadlineExceeded) || len(cell.callLog()) != 1 || ready.State != StateReady || ready.ProcessID == state.Nodes[0].Pressure.ProcessID {
				t.Fatalf("cached placement authorized another restart despite real readiness: err=%v ready=%+v calls=%v", err, ready, cell.callLog())
			}
			// New evidence reveals that the quiet shard lost the old copy on A.
			// Restarting B would leave only C, even though A is ready again.
			s.now = s.controller.replicasAfter.Add(time.Second)
			cell.replicas = func() (ReplicaSnapshot, error) {
				current := safeReplicaSnapshot(s.now, cell)
				current.Placements[1].LiveReplicas = []string{"gru-1-db-2", "gru-1-db-3"}
				return current, nil
			}
			state = observeState(t, testPolicy(), cell)
			if err := s.controller.rollingResize(t.Context(), state, big); err == nil || !strings.Contains(err.Error(), "would retain 1 live replicas") || len(cell.callLog()) != 1 {
				t.Fatalf("fresh placement failed to protect actual survivor quorum: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestDrainNeedsFreshPlacementBeforeTerminationAndRecovery(t *testing.T) {
	for _, evidence := range []string{"cached", "fresh quorum only"} {
		t.Run(evidence, func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			s.observe()
			s.now = s.now.Add(time.Second)
			s.controller.config.ReadyTimeout = waitTimeout
			cached := safeReplicaSnapshot(s.now, cell)
			cell.replicas = func() (ReplicaSnapshot, error) {
				if evidence == "fresh quorum only" && cell.state["gru-1-db-4"] == StateDrained {
					if !s.now.After(s.controller.replicasAfter) {
						s.now = s.controller.replicasAfter.Add(time.Second)
					}
					snapshot := safeReplicaSnapshot(s.now, cell)
					snapshot.Placements[1].LiveReplicas = []string{"gru-1-db-1", "gru-1-db-2"}
					return snapshot, nil
				}
				return cached, nil
			}
			state := observeState(t, policy, cell)
			action := Action{Kind: KindScaleIn, Node: "gru-1-db-4"}
			err := s.controller.apply(t.Context(), state, action)
			if err == nil || !slices.Equal(cell.callLog(), []string{"drain gru-1-db-4"}) {
				t.Fatalf("placement evidence authorized termination: err=%v calls=%v", err, cell.callLog())
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unexpected termination guard: %v", err)
			}
			s.controller.Resume()
			action.Recovery = true
			if err := s.controller.apply(t.Context(), state, action); err == nil || len(cell.callLog()) != 1 {
				t.Fatalf("recovery bypassed placement guard: err=%v calls=%v", err, cell.callLog())
			}
			// A strictly newer full replication inventory permits recovery,
			// without repeating the completed drain or chasing a moving floor.
			s.now = s.now.Add(MaxPressureClockSkew + time.Second)
			cell.replicas = func() (ReplicaSnapshot, error) { return safeReplicaSnapshot(s.now, cell), nil }
			// Successful recovery must tolerate scheduling delays in loaded race CI.
			s.controller.config.ReadyTimeout = 5 * time.Second
			if err := s.controller.apply(t.Context(), state, action); err != nil || !slices.Equal(cell.callLog(), []string{"drain gru-1-db-4", "terminate gru-1-db-4"}) {
				t.Fatalf("fresh fully replicated drain recovery failed: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestFirstObservedDrainRecoveryRequiresNewPlacementOnce(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	cell.state["gru-1-db-4"] = StateDrained
	cell.replicas = func() (ReplicaSnapshot, error) { return safeReplicaSnapshot(s.now, cell), nil }
	state, err := s.controller.observe(t.Context())
	if err != nil || state.Replicas != nil {
		t.Fatalf("first drained observation accepted preceding placement: state=%+v err=%v", state, err)
	}
	action := Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}
	if err := s.controller.apply(t.Context(), state, action); err == nil || len(cell.callLog()) != 0 {
		t.Fatalf("first recovery observation authorized termination: err=%v calls=%v", err, cell.callLog())
	}
	floor := s.controller.replicasAfter
	s.now = floor.Add(time.Second)
	if err := s.controller.apply(t.Context(), state, action); err != nil || !slices.Equal(cell.callLog(), []string{"terminate gru-1-db-4"}) {
		t.Fatalf("fresh stable drain recovery failed: err=%v calls=%v", err, cell.callLog())
	}
}

func TestUncertainRestartNeedsPlacementAfterRecoveredReadiness(t *testing.T) {
	cell := newFakeCell(3, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	s.observe()
	s.now = s.now.Add(time.Second)
	cached := safeReplicaSnapshot(s.now, cell)
	cell.replicas = func() (ReplicaSnapshot, error) { return cached, nil }
	state := observeState(t, testPolicy(), cell)
	s.controller.config.Cloud = lostResizeResponse{cell}
	big := Shape{OCPUs: 4, MemoryGB: 24}
	if err := s.controller.rollingResize(t.Context(), state, big); err == nil || len(cell.callLog()) != 1 {
		t.Fatalf("uncertain restart setup failed: err=%v calls=%v", err, cell.callLog())
	}
	s.controller.Resume()
	s.controller.config.Cloud = cell
	// OCI first reports STARTING, then the new process really becomes ready.
	for range 2 {
		s.now = s.now.Add(10 * time.Second)
		if _, err := s.controller.observe(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.controller.pendingRestarts) != 0 {
		t.Fatal("fresh process did not release the uncertain pressure fence")
	}
	state = observeState(t, testPolicy(), cell)
	if err := s.controller.rollingResize(t.Context(), state, big); err == nil || len(cell.callLog()) != 1 {
		t.Fatalf("old placement survived restart recovery: err=%v calls=%v", err, cell.callLog())
	}
	cell.replicas = nil
	s.controller.config.Members = liveReplicaInventory{cell, s.controller}
	s.now = s.controller.replicasAfter.Add(time.Second)
	state = observeState(t, testPolicy(), cell)
	if err := s.controller.rollingResize(t.Context(), state, big); err != nil || len(cell.callLog()) != 3 {
		t.Fatalf("fresh restart recovery failed: err=%v calls=%v", err, cell.callLog())
	}
}

func TestFreshReplicaConvergencePermitsRollingResizeWithIncreasingFloor(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	s.controller.config.Members = liveReplicaInventory{cell, s.controller}
	prior := s.controller.replicasAfter
	cell.onResize = func(string) {
		if len(cell.calls) > 1 && !s.controller.replicasAfter.After(prior) {
			t.Fatal("preceding convergence did not raise the placement floor")
		}
		prior = s.controller.replicasAfter
	}
	state := observeState(t, testPolicy(), cell)
	if err := s.controller.rollingResize(t.Context(), state, Shape{OCPUs: 4, MemoryGB: 24}); err != nil || len(cell.callLog()) != 4 || !s.controller.lastReplicas.SampledAt.After(s.controller.replicasAfter) {
		t.Fatalf("fresh placements did not converge all four nodes: err=%v calls=%v", err, cell.callLog())
	}
}
