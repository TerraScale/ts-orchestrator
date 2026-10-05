package cellscale

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type restartCache struct {
	*fakeCell
	before              map[string]NodePressure
	freezeAll           bool
	replayAfterReady    bool
	seenNewReady        bool
	oldSampleNewProcess bool
}

func (s *restartCache) Pressure(ctx context.Context, node string) (NodePressure, error) {
	if s.freezeAll || node == "gru-1-db-1" && s.replayAfterReady && s.seenNewReady {
		return s.before[node], nil
	}
	p, err := s.fakeCell.Pressure(ctx, node)
	if s.oldSampleNewProcess && p.ProcessID != s.before[node].ProcessID {
		p.SampledAt = s.before[node].SampledAt
	}
	if node == "gru-1-db-1" && p.State == StateReady && p.ProcessID != s.before[node].ProcessID {
		s.seenNewReady = true
	}
	return p, err
}

func TestRollingResizeNeedsPostRestartReadiness(t *testing.T) {
	for _, mode := range []string{"pre-restart ready cache", "old report after new ready", "new process with old sample"} {
		t.Run(mode, func(t *testing.T) {
			cell := newFakeCell(3, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			s.controller.config.ReadyTimeout = 20 * time.Millisecond
			observed := observeState(t, testPolicy(), cell)
			source := &restartCache{fakeCell: cell, before: map[string]NodePressure{},
				freezeAll: mode == "pre-restart ready cache", replayAfterReady: mode == "old report after new ready",
				oldSampleNewProcess: mode == "new process with old sample"}
			for _, node := range observed.Nodes {
				source.before[node.Name] = *node.Pressure
			}
			s.controller.config.Source = source
			if source.oldSampleNewProcess {
				s.now = s.now.Add(time.Second)
			}
			if source.freezeAll {
				cell.onResize = func(node string) {
					s.now = s.now.Add(time.Second)
					cell.state[node] = StateJoining // Actual member has not recovered.
				}
			}
			err := s.controller.rollingResize(t.Context(), observed, Shape{OCPUs: 4, MemoryGB: 24})
			if err == nil || len(cell.callLog()) != 1 {
				t.Fatalf("cached readiness overlapped restarts: %v, calls=%v", err, cell.callLog())
			}
			if source.freezeAll || source.oldSampleNewProcess {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("unexpected readiness failure: %v", err)
				}
				id, fence, pending := s.controller.restartFor(observed.Nodes[0].Name)
				if !pending || id != observed.Nodes[0].Identity() || fence.process != observed.Nodes[0].Pressure.ProcessID ||
					!sameShape(fence.shape, Shape{OCPUs: 4, MemoryGB: 24}) || fence.after.IsZero() {
					t.Fatal("cached pre-restart readiness released or altered restart progress")
				}
				if source.oldSampleNewProcess && (s.controller.activeIdentities[id.Name] != id ||
					s.controller.retiredIncarnations[NodeIdentity{Name: id.Name, Incarnation: id.Incarnation}]) {
					t.Fatal("old-timestamp successor retired the action's original identity")
				}
			} else {
				if !strings.Contains(err.Error(), "gru-1-db-1 is not ready") {
					t.Fatalf("predecessor replay was not refused as unknown readiness: %v", err)
				}
				assertIdentityInvalidated(t, s.controller, observed.Nodes[0].Identity())
				if !source.seenNewReady {
					t.Fatal("test never supplied valid successor readiness before replay")
				}
			}
		})
	}
}

func TestRollingResizeChecksActualPlacementQuorum(t *testing.T) {
	for _, evidence := range []string{"under-replicated", "missing", "stale"} {
		t.Run(evidence, func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			cell.replicas = func() (ReplicaSnapshot, error) {
				if !s.now.After(s.controller.replicasAfter) {
					s.now = s.controller.replicasAfter.Add(time.Second)
				}
				snapshot := safeReplicaSnapshot(s.now, cell)
				if evidence == "missing" {
					return ReplicaSnapshot{}, errors.New("inventory unavailable")
				}
				if evidence == "stale" {
					snapshot.SampledAt = s.now.Add(-MaxPressureAge - time.Second)
				} else {
					snapshot.Placements[1].LiveReplicas = []string{"gru-1-db-1", "gru-1-db-2"}
				}
				return snapshot, nil
			}
			observed := observeState(t, policy, cell)
			big := Shape{OCPUs: 4, MemoryGB: 24}
			if action, _ := rails(policy, observed, History{}, Action{Kind: KindResize, From: small, To: big}, 0); action.Kind != KindHold || action.Reason != ReasonQuorum {
				t.Fatalf("resize ignored actual placement quorum: %+v", action)
			}
			if err := s.controller.rollingResize(t.Context(), observed, big); err == nil || len(cell.callLog()) != 0 {
				t.Fatalf("unsafe restart with %s evidence: %v, calls=%v", evidence, err, cell.callLog())
			}
			cell.coresPerRequest = 1.0 / 150
			if action := act(policy, observeState(t, policy, cell), History{}); action.Kind != KindScaleOut {
				t.Fatalf("CPU growth should use safe horizontal capacity: %+v", action)
			}
		})
	}
}

func TestRollingResizeRechecksPlacementsBetweenRestarts(t *testing.T) {
	policy := testPolicy()
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, policy, cell, time.Minute)
	observed := observeState(t, policy, cell)
	cell.onResize = func(string) {
		cell.replicas = func() (ReplicaSnapshot, error) {
			if !s.now.After(s.controller.replicasAfter) {
				s.now = s.controller.replicasAfter.Add(time.Second)
			}
			snapshot := safeReplicaSnapshot(s.now, cell)
			snapshot.Placements[1].LiveReplicas = []string{"gru-1-db-1", "gru-1-db-2"}
			return snapshot, nil
		}
	}
	err := s.controller.rollingResize(t.Context(), observed, Shape{OCPUs: 4, MemoryGB: 24})
	if err == nil || !strings.Contains(err.Error(), "before restarting gru-1-db-2") || len(cell.callLog()) != 1 {
		t.Fatalf("continued rolling restart after placement lost copies: %v, calls=%v", err, cell.callLog())
	}
}

type lostResizeResponse struct{ *fakeCell }

func (c lostResizeResponse) Resize(ctx context.Context, id string, shape Shape) error {
	if err := c.fakeCell.Resize(ctx, id, shape); err != nil {
		return err
	}
	return errors.New("OCI accepted resize but response was lost")
}

func TestFailedResizeKeepsRestartFencedUntilRecovery(t *testing.T) {
	for _, failure := range []string{"readiness timeout", "lost OCI response", "controller restart"} {
		t.Run(failure, func(t *testing.T) {
			captureJournal(t)
			policy := testPolicy()
			policy.SustainUpSeconds, policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0, 0
			cell := newFakeCell(3, small, 2, 150)
			cell.coresPerRequest = 1.0 / 150
			s := newSim(t, policy, cell, 10*time.Second)
			s.controller.config.ReadyTimeout = 20 * time.Millisecond
			observed := s.observe()
			cache := &restartCache{fakeCell: cell, freezeAll: true, before: map[string]NodePressure{}}
			for _, node := range observed.Nodes {
				cache.before[node.Name] = *node.Pressure
			}
			s.controller.config.Source = cache
			if failure == "lost OCI response" {
				s.controller.config.Cloud = lostResizeResponse{cell}
			}
			// A fresh complete inventory and cached readiness still describe
			// the pre-restart cell, while its first member is actually joining.
			cell.replicas = func() (ReplicaSnapshot, error) { return *observed.Replicas, nil }
			cell.onResize = func(node string) { cell.state[node] = StateJoining }
			first, err := s.controller.Tick(t.Context())
			if first.Kind != KindResize || err == nil || len(cell.callLog()) != 1 {
				t.Fatalf("failed resize setup: %+v, %v, calls=%v", first, err, cell.callLog())
			}
			if failure == "readiness timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected readiness timeout: %v", err)
			}
			s.controller.Resume() // Resume must preserve uncertain restart evidence.
			if failure == "controller restart" {
				// Even zero cooldown cannot admit cached pre-start readiness
				// after the old controller's pending restart memory is lost.
				s.controller, err = New(s.controller.config)
				if err != nil {
					t.Fatal(err)
				}
				s.controller.config.Members = liveReplicaInventory{cell, s.controller}
			}
			for range 4 {
				s.now = s.now.Add(10 * time.Second)
				action, err := s.controller.Tick(t.Context())
				if err != nil || action.Kind != KindHold || action.Reason != ReasonNotSettled || len(cell.callLog()) != 1 {
					t.Fatalf("overlapped a pending restart: %+v, %v, calls=%v", action, err, cell.callLog())
				}
			}
			// Fresh proof from the recovered process releases the fence and
			// convergence continues with peers, without resizing db-1 again.
			cell.state["gru-1-db-1"] = StateReady
			cell.onResize, cell.replicas = nil, nil
			s.controller.config.Cloud, s.controller.config.Source = cell, cell
			action, err := s.controller.Tick(t.Context())
			if err != nil || action.Kind != KindResize || len(cell.callLog()) != 3 {
				t.Fatalf("recovered restart did not converge: %+v, %v, calls=%v", action, err, cell.callLog())
			}
		})
	}
}

type skewedRestartCache struct {
	*fakeCell
	earlier, later map[string]NodePressure
	starts         map[string]int
}

func (s skewedRestartCache) Pressure(_ context.Context, node string) (NodePressure, error) {
	if s.fakeCell.process[node] > s.starts[node] {
		return s.later[node], nil
	}
	return s.earlier[node], nil
}

func TestRollingResizeRejectsPreEffectSampleWithinClockSkew(t *testing.T) {
	cell := newFakeCell(3, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	s.controller.config.ReadyTimeout = 20 * time.Millisecond
	s.now = s.now.Add(time.Minute) // Both cached processes were observed after controller startup.
	observed := observeState(t, testPolicy(), cell)
	source := skewedRestartCache{fakeCell: cell, earlier: map[string]NodePressure{}, later: map[string]NodePressure{}, starts: map[string]int{}}
	for _, node := range observed.Nodes {
		earlier, later := *node.Pressure, *node.Pressure
		// Both samples predate the effect. The second was taken at T-1s
		// by a clock four seconds ahead, and belongs to a different process
		// than the first cached observation, yet still predates this resize.
		earlier.SampledAt = s.now.Add(-30 * time.Second)
		later.ProcessID, later.SampledAt = node.Name+"-p2", s.now.Add(3*time.Second)
		source.earlier[node.Name], source.later[node.Name] = earlier, later
		source.starts[node.Name] = cell.process[node.Name]
	}
	s.controller.config.Source = source
	// Discover membership using the earlier process, then measure placement.
	// No newer readiness has been accepted before the pre-effect cache.
	observed = s.observe()
	if observed.Replicas == nil {
		t.Fatal("pre-effect pressure and inventory did not establish a valid baseline")
	}
	for node, later := range source.later {
		later.SampledAt = s.now.Add(3 * time.Second)
		source.later[node] = later
	}
	cell.replicas = func() (ReplicaSnapshot, error) { return *observed.Replicas, nil }
	cell.onResize = func(node string) {
		s.now = s.now.Add(100 * time.Millisecond)
		cell.state[node] = StateJoining
	}
	err := s.controller.rollingResize(t.Context(), observed, Shape{OCPUs: 4, MemoryGB: 24})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pre-effect skewed sample escaped the shape evidence fence: %v", err)
	}
	old := observed.Nodes[0].Identity()
	id, fence, pending := s.controller.restartFor(old.Name)
	_, cached := s.controller.lastPressure[old]
	if !pending || id != old || fence.process != old.Incarnation || fence.after.IsZero() || cached ||
		s.controller.activeIdentities[old.Name] != old || !sameShape(fence.shape, Shape{OCPUs: 4, MemoryGB: 24}) {
		t.Fatal("pre-effect sample changed identity or released the original resize refusal")
	}
	if len(cell.callLog()) != 1 {
		t.Fatalf("clock skew authorized overlapping restarts: %v, calls=%v", err, cell.callLog())
	}
}
