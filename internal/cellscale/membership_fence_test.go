package cellscale

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestReadyMemberDiscoveryFencesDrainAndResize(t *testing.T) {
	for _, kind := range []Kind{KindScaleIn, KindResize} {
		t.Run(string(kind), func(t *testing.T) {
			captureJournal(t)
			policy := testPolicy()
			policy.SustainDownSeconds, policy.ScaleDownBelow = 0, 0.9
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			// Peers serve safely, but cannot fit the new member's whole disk load.
			s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
				if p.Node != "gru-1-db-5" {
					p.DiskTotalBytes = 90 << 30
				}
			}}
			if state := s.observe(); state.Replicas == nil {
				t.Fatal("initial membership/inventory was not accepted")
			}
			s.now = s.now.Add(time.Second)
			snapshot := safeReplicaSnapshot(s.now, cell)
			cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
			if state := s.observe(); state.Replicas == nil {
				t.Fatal("baseline inventory was not accepted")
			}
			added := newFakeCell(5, small, 0, 0).instances[4]
			action := Action{Kind: KindScaleIn, Node: added.Name}
			if kind == KindResize {
				added.Shape = Shape{OCPUs: 4, MemoryGB: 24}
				action = Action{Kind: KindResize, From: small, To: added.Shape}
			}
			cell.instances = append(cell.instances, added)
			cell.state[added.Name], cell.release[added.Name], cell.process[added.Name] = StateReady, "r1", 1
			s.now = s.now.Add(time.Second)
			discovered := s.now
			for _, offset := range []time.Duration{0, 3 * time.Second, MaxPressureClockSkew} {
				s.now = discovered.Add(offset)
				if offset > 0 {
					snapshot.SampledAt = s.now
				}
				state := s.observe()
				if state.Replicas != nil || slices.ContainsFunc(state.Nodes, func(n Node) bool { return !n.ready() }) ||
					!s.controller.replicasAfter.Equal(discovered.Add(MaxPressureClockSkew)) ||
					s.controller.lastReplicas != nil {
					t.Fatalf("ready discovery failed to invalidate predecessor inventory at %s: %+v", offset, state)
				}
				if got, err := s.controller.Tick(t.Context()); err != nil || got.Kind != KindHold || got.Reason != ReasonQuorum {
					t.Fatalf("tick admitted pre-join inventory: action=%+v err=%v", got, err)
				}
				if err := s.controller.apply(t.Context(), state, action); err == nil || !strings.Contains(err.Error(), "replica inventory unavailable") || len(cell.callLog()) != 0 {
					t.Fatalf("recheck admitted pre-join inventory: err=%v calls=%v", err, cell.callLog())
				}
			}
			// Freshness alone cannot authorize an unsafe newly introduced shard.
			s.now = s.controller.replicasAfter.Add(time.Second)
			snapshot = safeReplicaSnapshot(s.now, cell)
			snapshot.Placements = append(snapshot.Placements, ReplicaPlacement{Org: "new", Database: "introduced", Shard: 1,
				LiveReplicas: []string{added.Name}})
			state := s.observe()
			if state.Replicas == nil {
				t.Fatal("strictly post-discovery inventory was not observed")
			}
			if got, err := s.controller.Tick(t.Context()); err != nil || got.Kind != KindHold || got.Reason != ReasonQuorum {
				t.Fatalf("unsafe new placement passed rail: action=%+v err=%v", got, err)
			}
			wantError := "no destination that fits"
			if kind == KindResize {
				wantError = "would retain 1 live replicas, need 2"
			}
			if err := s.controller.apply(t.Context(), state, action); err == nil || !strings.Contains(err.Error(), wantError) || len(cell.callLog()) != 0 {
				t.Fatalf("unsafe new placement authorized effects: err=%v calls=%v", err, cell.callLog())
			}
			// Measure a safe inventory, including the new placement, after every effect.
			s.now = s.now.Add(time.Second)
			cell.replicas = func() (ReplicaSnapshot, error) {
				if !s.now.After(s.controller.replicasAfter) {
					s.now = s.controller.replicasAfter.Add(time.Second)
				}
				fresh := safeReplicaSnapshot(s.now, cell)
				fresh.Placements = append(fresh.Placements, ReplicaPlacement{Org: "new", Database: "introduced", Shard: 1,
					LiveReplicas: []string{"gru-1-db-1", "gru-1-db-2", "gru-1-db-3"}})
				return fresh, nil
			}
			wantEffects := 2 // Drain and terminate the new member.
			if kind == KindResize {
				wantEffects = 4 // The new member already has the larger shape.
			}
			if got, err := s.controller.Tick(t.Context()); err != nil || got.Kind != kind || len(cell.callLog()) != wantEffects {
				t.Fatalf("safe new placement did not permit progress: action=%+v err=%v calls=%v", got, err, cell.callLog())
			}
		})
	}
}

func TestFirstNonemptyDiscoveryRequiresPostDiscoveryInventory(t *testing.T) {
	for _, baseline := range []string{"unobserved", "empty", "foreign"} {
		t.Run(baseline, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			owned := slices.Clone(cell.instances)
			floor := s.controller.replicasAfter
			if baseline != "unobserved" {
				cell.instances = nil
				if baseline == "foreign" {
					cell.instances = slices.Clone(owned)
					for i := range cell.instances {
						cell.instances[i].Foreign = true
					}
				}
				if state := s.observe(); len(state.Nodes) != 0 || !s.controller.replicasAfter.Equal(floor) {
					t.Fatalf("empty ownership observation changed startup floor: %+v", state)
				}
			}
			cell.instances = owned
			s.now = s.start.Add(30 * time.Second)
			// Readiness and inventory were measured before our delayed first OCI listing.
			cache := &restartCache{fakeCell: cell, freezeAll: true, before: map[string]NodePressure{}}
			for _, instance := range owned {
				p, err := cell.Pressure(t.Context(), instance.Name)
				if err != nil {
					t.Fatal(err)
				}
				cache.before[instance.Name] = p
			}
			s.controller.config.Source = cache
			snapshot := safeReplicaSnapshot(s.now, cell)
			cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
			s.now = s.start.Add(time.Minute)
			state := s.observe()
			if state.Replicas != nil || slices.ContainsFunc(state.Nodes, func(n Node) bool { return !n.ready() }) ||
				!s.controller.replicasAfter.Equal(s.now.Add(MaxPressureClockSkew)) ||
				!s.controller.lastReplicas.SampledAt.Equal(snapshot.SampledAt) {
				t.Fatalf("post-start/pre-discovery evidence was accepted or lost: %+v", state)
			}
			for _, action := range []Action{{Kind: KindScaleIn, Node: "gru-1-db-4"}, {Kind: KindResize, From: small, To: Shape{OCPUs: 4, MemoryGB: 24}}} {
				if err := s.controller.apply(t.Context(), state, action); err == nil || len(cell.callLog()) != 0 {
					t.Fatalf("first listing authorized %s: err=%v calls=%v", action.Kind, err, cell.callLog())
				}
			}
			s.now = s.controller.replicasAfter
			snapshot.SampledAt = s.now
			if state := s.observe(); state.Replicas != nil {
				t.Fatal("inventory at the full-skew boundary was accepted")
			}
			s.now = s.now.Add(time.Second)
			snapshot.SampledAt = s.now
			if state := s.observe(); state.Replicas == nil {
				t.Fatal("stable first discovery kept moving the inventory floor")
			}
		})
	}
}

func TestMembershipChangesFenceMutationRechecks(t *testing.T) {
	for _, change := range []string{"same name/new ID", "removal", "foreign to owned", "owned to foreign"} {
		for _, kind := range []Kind{KindScaleIn, KindResize} {
			t.Run(change+"/"+string(kind), func(t *testing.T) {
				cell := newFakeCell(5, small, 2, 150)
				if change == "foreign to owned" {
					cell.instances[4].Foreign = true
				}
				s := newSim(t, testPolicy(), cell, time.Minute)
				state := s.observe()
				if state.Replicas == nil {
					t.Fatal("baseline inventory was not accepted")
				}
				snapshot := *state.Replicas
				cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
				cache := &restartCache{fakeCell: cell, freezeAll: true, before: map[string]NodePressure{}}
				for _, node := range state.Nodes {
					cache.before[node.Name] = *node.Pressure
				}
				// Adoption is already ready when first observed; replacements replay identical evidence.
				p, err := cell.Pressure(t.Context(), "gru-1-db-5")
				if err != nil {
					t.Fatal(err)
				}
				cache.before[p.Node] = p
				s.controller.config.Source = cache
				priorID := state.Nodes[0].Identity()
				priorPressure := s.controller.lastPressure[priorID]
				s.now = s.now.Add(time.Second)
				switch change {
				case "same name/new ID":
					cell.instances[0].ID = "replacement-ocid"
				case "removal":
					cell.instances = cell.instances[:4]
				case "foreign to owned":
					cell.instances[4].Foreign = false
				case "owned to foreign":
					cell.instances[4].Foreign = true
				}
				action := Action{Kind: kind, Node: "gru-1-db-4", From: small, To: Shape{OCPUs: 4, MemoryGB: 24}}
				// No intervening observe: apply's shared recheck must discover the change.
				if err := s.controller.apply(t.Context(), state, action); err == nil || len(cell.callLog()) != 0 ||
					!s.controller.replicasAfter.Equal(s.now.Add(MaxPressureClockSkew)) ||
					s.controller.replicasAfter.Before(snapshot.SampledAt) {
					t.Fatalf("membership recheck lost its fence/history: err=%v calls=%v", err, cell.callLog())
				}
				if change == "same name/new ID" {
					assertIdentityInvalidated(t, s.controller, priorID)
					if s.controller.lastReplicas != nil {
						t.Fatal("replacement retained predecessor inventory")
					}
				} else if !reflect.DeepEqual(priorPressure, s.controller.lastPressure[priorID]) {
					t.Fatal("membership change altered an unchanged peer's pressure")
				}
				if state := s.observe(); state.Replicas != nil {
					t.Fatal("stable follow-up observation replayed pre-change inventory")
				}
			})
		}
	}
}

type reorderedMembership struct {
	*fakeCell
	reverse bool
}

func (c reorderedMembership) List(ctx context.Context) ([]Instance, error) {
	instances, err := c.fakeCell.List(ctx)
	if c.reverse {
		slices.Reverse(instances)
	}
	return instances, err
}

func TestStableMembershipOrderingDoesNotAdvanceFence(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	state := s.observe()
	if state.Replicas == nil {
		t.Fatal("initial inventory was not accepted")
	}
	snapshot := *state.Replicas
	cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
	floor := s.controller.replicasAfter
	for i := range 4 {
		s.now = s.now.Add(time.Second)
		s.controller.config.Cloud = reorderedMembership{cell, i%2 == 0}
		if state := s.observe(); state.Replicas == nil || !s.controller.replicasAfter.Equal(floor) {
			t.Fatalf("unchanged membership/order kept fencing inventory: %+v", state)
		}
	}
}

func TestMembershipReplacementInvalidatesProgressAndRetainsRefusals(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "newer unready sample", true: "pending restart"}[pending], func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			state := s.observe()
			ready := *state.Nodes[0].Pressure
			fence := restartFence{shape: small, process: ready.ProcessID, after: s.now.Add(MaxPressureClockSkew)}
			if pending {
				s.controller.pendingRestarts[ready.Identity()] = fence
			} else {
				s.now = s.now.Add(time.Second)
				unready := ready
				unready.SampledAt, unready.State = s.now, StateJoining
				if !s.controller.pressureUsable(ready.Node, unready) {
					t.Fatal("newer unready sample was not retained")
				}
			}
			highWater := s.controller.pressureHighWater[ready.Node]
			s.controller.config.Source = replayedReadiness{cell, ready}
			cell.instances[0].ID = "replacement-ocid"
			s.now = s.now.Add(time.Second)
			discovered := s.now
			// Global action/failure history survives; tuple-owned progress does not.
			history := History{Failures: 2, LastAction: s.now, Actions: []time.Time{s.now}}
			s.controller.history = history
			current := s.observe()
			assertIdentityInvalidated(t, s.controller, ready.Identity())
			if current.Nodes[0].Pressure != nil || s.controller.lastReplicas != nil || len(s.controller.restartBarriers) != 0 ||
				!reflect.DeepEqual(history, s.controller.History()) || s.controller.pressureHighWater[ready.Node].Before(highWater) ||
				s.controller.pressureAfter[ready.Node].Before(discovered.Add(MaxPressureClockSkew)) ||
				!s.controller.retiredInstances[NodeIdentity{Name: ready.Node, InstanceID: ready.InstanceID}] {
				t.Fatalf("replacement inherited progress or lost refusal metadata: %+v", current)
			}
			if err := s.controller.apply(t.Context(), current, Action{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}}); err == nil || len(cell.callLog()) != 0 {
				t.Fatalf("replacement refusal allowed a mutation: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestMembershipFenceRetainsInventoryHighWaterAndConflicts(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	initial := s.observe()
	if initial.Replicas == nil {
		t.Fatal("initial inventory was not accepted")
	}
	cell.instances[0].ID = "replacement-ocid"
	cell.process[cell.instances[0].Name]++ // The replacement has its own process start.
	s.now = s.now.Add(time.Second)
	// Discover the OCI replacement before collecting its full new identity.
	s.controller.trackPressureIdentities(cell.instances)
	s.now = s.controller.pressureAfter[cell.instances[0].Name].Add(time.Second)
	if state := s.observe(); state.Nodes[0].Pressure == nil {
		t.Fatal("fresh successor pressure was not accepted")
	}
	s.now = s.now.Add(time.Second)
	s.controller.fenceReplicas()
	snapshot := safeReplicaSnapshot(s.now.Add(3*time.Second), cell)
	cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
	if state := s.observe(); state.Replicas != nil || !s.controller.lastReplicas.SampledAt.Equal(snapshot.SampledAt) {
		t.Fatal("fenced inventory did not retain its newer timestamp")
	}
	healthy := snapshot
	snapshot = safeReplicaSnapshot(snapshot.SampledAt, cell)
	snapshot.Placements[1].LiveReplicas = []string{"gru-1-db-1"}
	if state := s.observe(); state.Replicas != nil || s.controller.lastReplicas.Complete {
		t.Fatal("fenced contradiction did not poison its timestamp")
	}
	s.now = s.controller.replicasAfter.Add(time.Second)
	snapshot = healthy
	if state := s.observe(); state.Replicas != nil || s.controller.lastReplicas == nil || s.controller.lastReplicas.Complete ||
		!s.controller.lastReplicas.SampledAt.Equal(healthy.SampledAt) {
		t.Fatal("same-identity replay discarded poisoned high-water evidence")
	}
	snapshot = *initial.Replicas // Keep the captured predecessor member identities.
	if state := s.observe(); state.Replicas != nil || s.controller.lastReplicas != nil || s.controller.replicasAfter.Before(healthy.SampledAt) {
		t.Fatal("predecessor inventory survived invalidation or lowered the refusal floor")
	}
	snapshot = healthy
	if state := s.observe(); state.Replicas != nil || s.controller.replicasAfter.Before(healthy.SampledAt) {
		t.Fatal("clearing predecessor inventory resolved a poisoned timestamp by replay")
	}
	snapshot = safeReplicaSnapshot(s.now, cell)
	if state := s.observe(); state.Replicas == nil {
		t.Fatal("strictly newer post-membership inventory did not recover")
	}
}

func TestMembershipChangesCannotLowerFenceOnClockRegression(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	initial := s.observe()
	snapshot := *initial.Replicas
	cell.replicas = func() (ReplicaSnapshot, error) { return snapshot, nil }
	s.now = s.now.Add(30 * time.Second)
	cell.instances[0].ID = "replacement-ocid"
	s.observe()
	floor := s.controller.replicasAfter
	s.now = s.now.Add(-time.Second)
	cell.instances[0].ID = "another-replacement-ocid"
	s.observe()
	if !s.controller.replicasAfter.Equal(floor) {
		t.Fatal("identity change with a backwards clock lowered the inventory floor")
	}
	cell.instances = cell.instances[:3]
	s.now = s.now.Add(-time.Second)
	s.observe()
	if !s.controller.replicasAfter.Equal(floor) {
		t.Fatal("removal with a backwards clock lowered the inventory floor")
	}
}
