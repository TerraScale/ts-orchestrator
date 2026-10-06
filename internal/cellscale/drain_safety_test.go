package cellscale

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func drainingReplicaSnapshot(now time.Time) ReplicaSnapshot {
	snapshot := safeReplicaSnapshot(now)
	for i := range snapshot.Placements {
		snapshot.Placements[i].LiveReplicas = []string{"gru-1-db-1", "gru-1-db-2", "gru-1-db-4"}
	}
	return snapshot
}

func TestDrainPreparesReplacementBeforeFullSurvivorFloor(t *testing.T) {
	policy := testPolicy()
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, policy, cell, time.Minute)
	prepared := false
	cell.replicas = func() (ReplicaSnapshot, error) {
		if !s.now.After(s.controller.replicasAfter) {
			s.now = s.controller.replicasAfter.Add(time.Second)
		}
		if prepared {
			return safeReplicaSnapshot(s.now), nil
		}
		return drainingReplicaSnapshot(s.now), nil
	}
	state, err := s.controller.observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := removalSafe(policy, state, "gru-1-db-4"); err == nil {
		t.Fatal("setup already had full surviving RF")
	}
	action := act(policy, state, History{})
	if action.Kind != KindScaleIn {
		t.Fatalf("RF3 on four nodes did not start drain: %+v", action)
	}
	cell.after = map[string]func(string){"drain": func(node string) {
		if node != "gru-1-db-4" || prepared {
			t.Fatalf("unexpected drain %s", node)
		}
		// TerraBase prepares the missing copy on non-replica peer 3 during Drain.
		prepared = true
	}}
	if err := s.controller.apply(t.Context(), state, action); err != nil || !prepared ||
		!slices.Equal(cell.callLog(), []string{"drain gru-1-db-4", "terminate gru-1-db-4"}) || cell.nodes() != 3 {
		t.Fatalf("two-gate scale-in failed: err=%v prepared=%v calls=%v", err, prepared, cell.callLog())
	}
	three := observeState(t, policy, newFakeCell(3, small, 2, 150))
	if err := drainSafe(policy, three, "gru-1-db-3"); err == nil {
		t.Fatal("RF3 on three nodes passed the start gate")
	}
	if got, _ := rails(policy, three, History{}, Action{Kind: KindScaleIn, Node: "gru-1-db-3"}, 0); got.Kind != KindHold {
		t.Fatalf("RF3 on three nodes started drain: %+v", got)
	}
}

func TestDrainDestinationFitsWholeMeasuredLoad(t *testing.T) {
	policy := testPolicy()
	for _, test := range []struct {
		name   string
		change func(from, to *Node)
		fits   bool
	}{
		{"fit", func(*Node, *Node) {}, true},
		{"CPU actual OCPUs", func(from, to *Node) {
			from.Shape.OCPUs, from.Pressure.CPUUtil = 8, 0.2
			to.Pressure.CPUUtil = 0.1
		}, false},
		{"memory actual GB", func(from, to *Node) {
			from.Shape.MemoryGB, from.Pressure.MemoryUtil = 48, 0.2
			to.Pressure.MemoryUtil = 0.1
		}, false},
		{"disk destination capacity", func(from, to *Node) {
			from.Pressure.DiskUsedBytes = 300 << 30
			to.Pressure.DiskTotalBytes = 400 << 30
		}, false},
		{"disk overflow", func(from, to *Node) {
			from.Pressure.DiskUsedBytes, from.Pressure.DiskTotalBytes = math.MaxInt64-1, math.MaxInt64
			to.Pressure.DiskUsedBytes, to.Pressure.DiskTotalBytes = math.MaxInt64-1, math.MaxInt64
		}, false},
		{"IOPS", func(from, to *Node) { from.Pressure.DiskIOPS = policy.Targets.DiskIOPS - to.Pressure.DiskIOPS }, false},
		{"requests", func(from, to *Node) { from.Pressure.RequestRate = policy.Targets.RequestRate - to.Pressure.RequestRate }, false},
		{"queue", func(from, to *Node) {
			from.Pressure.IOQueueDepth = policy.Targets.IOQueueDepth - to.Pressure.IOQueueDepth
		}, false},
		{"p95", func(from, to *Node) {
			from.Pressure.P95LatencyMS = policy.Targets.P95LatencyMS - to.Pressure.P95LatencyMS
		}, false},
		{"stale destination", func(_ *Node, to *Node) {
			to.Pressure.SampledAt = to.Pressure.SampledAt.Add(-MaxPressureAge - time.Second)
		}, false},
		{"unready destination", func(_ *Node, to *Node) { to.Pressure.State = StateJoining }, false},
		{"lagging destination", func(_ *Node, to *Node) { to.Pressure.Load.ReplicationLagSeq = policy.MaxReplicationLagSeq + 1 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := observeState(t, policy, newFakeCell(4, small, 2, 150))
			snapshot := drainingReplicaSnapshot(state.Now)
			state.Replicas = &snapshot
			test.change(&state.Nodes[3], &state.Nodes[2])
			if err := drainSafe(policy, state, "gru-1-db-4"); (err == nil) != test.fits {
				t.Fatalf("destination gate = %v, want fit=%v", err, test.fits)
			}
		})
	}
	state := observeState(t, policy, newFakeCell(4, small, 2, 150))
	snapshot := drainingReplicaSnapshot(state.Now)
	for i := range snapshot.Placements {
		snapshot.Placements[i].LiveReplicas = append(snapshot.Placements[i].LiveReplicas, "gru-1-db-3")
	}
	state.Replicas = &snapshot
	if err := drainSafe(policy, state, "gru-1-db-4"); err != nil {
		t.Fatalf("existing ready replicas cannot receive workload without another replica slot: %v", err)
	}
}

func TestDrainRechecksFreshDestinationFit(t *testing.T) {
	policy := testPolicy()
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, policy, cell, time.Minute)
	s.observe()
	s.now = s.now.Add(time.Second)
	cell.replicas = func() (ReplicaSnapshot, error) { return drainingReplicaSnapshot(s.now), nil }
	state, err := s.controller.observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	action := act(policy, state, History{})
	if action.Kind != KindScaleIn {
		t.Fatalf("initial fit did not plan scale-in: %+v", action)
	}
	s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
		if p.Node == "gru-1-db-3" {
			p.CPUUtil = 0.65 // Cell pressure still fits; this sole replacement destination does not.
		}
	}}
	if err := s.controller.apply(t.Context(), state, action); err == nil || !strings.Contains(err.Error(), "no destination that fits") || len(cell.callLog()) != 0 {
		t.Fatalf("fresh destination did not block Drain: err=%v calls=%v", err, cell.callLog())
	}
}

func TestDrainRejectsUnknownAndStaleInventory(t *testing.T) {
	for _, evidence := range []string{"missing", "partial", "stale", "unknown member"} {
		t.Run(evidence, func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			state := observeState(t, policy, cell)
			snapshot := drainingReplicaSnapshot(s.now)
			switch evidence {
			case "partial":
				snapshot.Complete = false
			case "stale":
				snapshot.SampledAt = s.now.Add(-MaxPressureAge - time.Second)
			case "unknown member":
				snapshot.Placements[1].LiveReplicas = append(snapshot.Placements[1].LiveReplicas, "gru-1-db-5")
			}
			cell.replicas = func() (ReplicaSnapshot, error) {
				if evidence == "missing" {
					return ReplicaSnapshot{}, errors.New("inventory unavailable")
				}
				return snapshot, nil
			}
			current, err := s.controller.observe(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := rails(policy, current, History{}, Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, 0); got.Kind != KindHold || got.Reason != ReasonQuorum {
				t.Fatalf("invalid inventory passed start rail: %+v", got)
			}
			if err := s.controller.apply(t.Context(), state, Action{Kind: KindScaleIn, Node: "gru-1-db-4"}); err == nil || len(cell.callLog()) != 0 {
				t.Fatalf("invalid inventory authorized Drain: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestCompletedDrainProtectsEveryPlacement(t *testing.T) {
	for _, evidence := range []string{"missing copy", "no quorum", "copy not ready", "unknown member"} {
		t.Run(evidence, func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			cell.replicas = func() (ReplicaSnapshot, error) {
				if !s.now.After(s.controller.replicasAfter) {
					s.now = s.controller.replicasAfter.Add(time.Second)
				}
				if cell.state["gru-1-db-4"] != StateDrained {
					return drainingReplicaSnapshot(s.now), nil
				}
				snapshot := safeReplicaSnapshot(s.now)
				switch evidence {
				case "missing copy":
					snapshot.Placements[1].LiveReplicas = snapshot.Placements[1].LiveReplicas[:2]
				case "no quorum":
					snapshot.Placements[1].LiveReplicas = snapshot.Placements[1].LiveReplicas[:1]
				case "unknown member":
					snapshot.Placements[1].LiveReplicas = append(snapshot.Placements[1].LiveReplicas, "gru-1-db-5")
				}
				return snapshot, nil
			}
			state, err := s.controller.observe(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if evidence == "copy not ready" {
				cell.after = map[string]func(string){"drain": func(string) { cell.state["gru-1-db-3"] = StateJoining }}
			}
			if err := s.controller.apply(t.Context(), state, Action{Kind: KindScaleIn, Node: "gru-1-db-4"}); err == nil ||
				!slices.Equal(cell.callLog(), []string{"drain gru-1-db-4"}) || cell.nodes() != 4 {
				t.Fatalf("incomplete placement authorized Terminate: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

type completingDrain struct {
	*fakeCell
	reads int
}

func (s *completingDrain) Pressure(ctx context.Context, node string) (NodePressure, error) {
	if node == "gru-1-db-4" && s.state[node] == StateDraining {
		s.reads++
		if s.reads == 3 { // Observation and final probe see draining; the wait sees completion.
			s.state[node], s.delayedSample[node] = StateDrained, true
		}
	}
	return s.fakeCell.Pressure(ctx, node)
}

func TestDrainingRecoveryWaitsForReplacementWithoutRepeatingDrain(t *testing.T) {
	policy := testPolicy()
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, policy, cell, time.Minute)
	cell.state["gru-1-db-4"] = StateDraining
	cell.replicas = func() (ReplicaSnapshot, error) {
		if !s.now.After(s.controller.replicasAfter) {
			s.now = s.controller.replicasAfter.Add(time.Second)
		}
		if cell.state["gru-1-db-4"] == StateDrained {
			return safeReplicaSnapshot(s.now), nil
		}
		return drainingReplicaSnapshot(s.now), nil
	}
	state, err := s.controller.observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	action, _ := Decide(policy, state, History{})
	if action.Kind != KindScaleIn || !action.Recovery || removalSafe(policy, state, action.Node) == nil {
		t.Fatalf("draining recovery demanded completed RF: %+v", action)
	}
	s.controller.config.Source = &completingDrain{fakeCell: cell}
	if err := s.controller.apply(t.Context(), state, action); err != nil || !slices.Equal(cell.callLog(), []string{"terminate gru-1-db-4"}) {
		t.Fatalf("draining recovery failed: err=%v calls=%v", err, cell.callLog())
	}
}

type replicaFallback struct {
	liveReplicaInventory
	read func(context.Context, string) (ReplicaSnapshot, error)
}

func (m replicaFallback) Replicas(ctx context.Context, node string) (ReplicaSnapshot, error) {
	return m.read(ctx, node)
}

func TestReplicaInventoryFallsBackForObservationsAndConvergence(t *testing.T) {
	for _, failure := range []string{"transport", "stale", "invalid", "unknown member", "all fail"} {
		for _, kind := range []Kind{KindScaleIn, KindResize} {
			t.Run(failure+"/"+string(kind), func(t *testing.T) {
				// Exercise fallback and timeout under virtual time, not runner load.
				synctest.Test(t, func(t *testing.T) {
					policy := testPolicy()
					cell := newFakeCell(4, small, 2, 150)
					s := newSim(t, policy, cell, time.Minute)
					s.controller.config.ReadyTimeout = waitTimeout
					live := liveReplicaInventory{cell, s.controller}
					secondReads := 0
					s.controller.config.Members = replicaFallback{live, func(ctx context.Context, node string) (ReplicaSnapshot, error) {
						if node == "gru-1-db-1" || failure == "all fail" {
							switch failure {
							case "stale":
								return safeReplicaSnapshot(s.now.Add(-MaxPressureAge - time.Second)), nil
							case "invalid":
								snapshot := safeReplicaSnapshot(s.now)
								snapshot.Complete = false
								return snapshot, nil
							case "unknown member":
								snapshot := safeReplicaSnapshot(s.now)
								snapshot.Placements[0].LiveReplicas = append(snapshot.Placements[0].LiveReplicas, "gru-1-db-5")
								s.now = s.now.Add(time.Second)
								return snapshot, nil
							default:
								return ReplicaSnapshot{}, errors.New("inventory endpoint unavailable")
							}
						}
						if node == "gru-1-db-2" {
							secondReads++
						}
						return live.Replicas(ctx, node)
					}}
					state, err := s.controller.observe(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					action := Action{Kind: KindScaleIn, Node: "gru-1-db-4"}
					if kind == KindResize {
						action = Action{Kind: KindResize, From: small, To: Shape{OCPUs: 4, MemoryGB: 24}}
					}
					if failure == "all fail" {
						if state.Replicas != nil {
							t.Fatal("unavailable endpoints produced an inventory")
						}
						if got, _ := rails(policy, state, History{}, action, 0); got.Kind != KindHold || got.Reason != ReasonQuorum {
							t.Fatalf("unknown inventory did not hold: %+v", got)
						}
						if err := s.controller.apply(t.Context(), state, action); err == nil || len(cell.callLog()) != 0 {
							t.Fatalf("unknown inventory authorized mutation: err=%v calls=%v", err, cell.callLog())
						}
						if err := s.controller.waitReplicas(t.Context(), names(state.Nodes), state); !errors.Is(err, context.DeadlineExceeded) {
							t.Fatalf("unavailable convergence wait ignored timeout: %v", err)
						}
						return
					}
					if state.Replicas == nil || secondReads != 1 {
						t.Fatalf("second fresh endpoint was not observed: inventory=%+v reads=%d", state.Replicas, secondReads)
					}
					want := 2
					if kind == KindResize {
						want = 4
					}
					if err := s.controller.apply(t.Context(), state, action); err != nil || len(cell.callLog()) != want || secondReads <= 1 {
						t.Fatalf("fallback did not finish convergence: err=%v calls=%v reads=%d", err, cell.callLog(), secondReads)
					}
				})
			})
		}
	}
}

func TestUnknownMemberInventoryRetainsTimestampFloor(t *testing.T) {
	for _, offset := range []time.Duration{-time.Second, 0, time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			s.observe()
			s.now = s.now.Add(time.Second)
			if offset <= 0 {
				// Only refused evidence must time out; the accepted case keeps
				// the default deadline so a loaded runner cannot fail it.
				s.controller.config.ReadyTimeout = waitTimeout
			}
			unknown := safeReplicaSnapshot(s.now)
			unknown.Members = append(unknown.Members, fakeNodeIdentity("gru-1-db-5"))
			unknown.Placements[0].LiveReplicas = append(unknown.Placements[0].LiveReplicas, "gru-1-db-5")
			peer := safeReplicaSnapshot(s.now.Add(offset))
			peerReads := 0
			s.controller.config.Members = replicaFallback{liveReplicaInventory{cell, s.controller}, func(_ context.Context, node string) (ReplicaSnapshot, error) {
				if node == "gru-1-db-1" {
					return unknown, nil
				}
				peerReads++
				if offset > 0 && peerReads > 1 {
					// Each convergence poll measures new placement after the
					// mismatched peer discards the previous usable inventory.
					s.now = s.now.Add(time.Second)
					peer.SampledAt = s.now.Add(offset)
				}
				return peer, nil
			}}
			state, err := s.controller.observe(t.Context())
			if err != nil || peerReads == 0 || (state.Replicas != nil) != (offset > 0) || s.controller.replicasAfter.Before(unknown.SampledAt) {
				t.Fatalf("membership fallback lost timestamp fence: inventory=%+v peers=%d err=%v", state.Replicas, peerReads, err)
			}
			err = s.controller.waitReplicas(t.Context(), names(state.Nodes), state)
			if offset > 0 && err != nil || offset <= 0 && !errors.Is(err, context.DeadlineExceeded) || len(cell.callLog()) != 0 {
				t.Fatalf("convergence accepted old or unknown placement evidence: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestReplicaFallbackCannotReplayHealthyInventoryOverContradiction(t *testing.T) {
	policy := testPolicy()
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, policy, cell, time.Minute)
	s.observe()
	s.now = s.now.Add(time.Second)
	previous := safeReplicaSnapshot(s.now, cell)
	if !s.controller.replicasUsable(previous) {
		t.Fatal("initial inventory rejected")
	}
	s.now = s.now.Add(time.Second)
	under := safeReplicaSnapshot(s.now)
	under.Placements[1].LiveReplicas = under.Placements[1].LiveReplicas[:2]
	if !s.controller.replicasUsable(under) {
		t.Fatal("fresh under-replicated evidence rejected")
	}
	conflict := safeReplicaSnapshot(s.now)
	s.controller.config.Members = replicaFallback{liveReplicaInventory{cell, s.controller}, func(_ context.Context, node string) (ReplicaSnapshot, error) {
		if node == "gru-1-db-1" {
			return conflict, nil
		}
		if node == "gru-1-db-2" {
			return under, nil
		}
		return previous, nil
	}}
	state, err := s.controller.observe(t.Context())
	if err != nil || state.Replicas != nil || s.controller.lastReplicas.Complete {
		t.Fatalf("fallback resolved poisoned inventory by replay: state=%+v err=%v", state, err)
	}
	if err := s.controller.apply(t.Context(), state, Action{Kind: KindScaleIn, Node: "gru-1-db-4"}); err == nil || len(cell.callLog()) != 0 {
		t.Fatalf("contradiction authorized Drain: err=%v calls=%v", err, cell.callLog())
	}
	s.now = s.now.Add(time.Second)
	live := liveReplicaInventory{cell, s.controller}
	s.controller.config.Members = replicaFallback{live, func(ctx context.Context, node string) (ReplicaSnapshot, error) {
		if node == "gru-1-db-1" {
			return conflict, nil
		}
		return live.Replicas(ctx, node)
	}}
	state, err = s.controller.observe(t.Context())
	if err != nil || state.Replicas == nil || !state.Replicas.SampledAt.After(conflict.SampledAt) {
		t.Fatalf("newer fallback did not recover: state=%+v err=%v", state, err)
	}
	if err := s.controller.apply(t.Context(), state, Action{Kind: KindScaleIn, Node: "gru-1-db-4"}); err != nil || len(cell.callLog()) != 2 {
		t.Fatalf("fresh recovery failed: err=%v calls=%v", err, cell.callLog())
	}
}
