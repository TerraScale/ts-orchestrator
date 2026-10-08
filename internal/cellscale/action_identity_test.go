package cellscale

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

func requireIdentityFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "cell membership changed") {
		t.Fatalf("expected original node identity mismatch, got %v", err)
	}
}

func TestActionIdentityRecheckRejectsReplacementWithFreshInventory(t *testing.T) {
	for _, test := range []struct {
		name   string
		action Action
		state  NodeState
	}{
		{"launch", Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}, StateReady},
		{"drain", Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, StateReady},
		{"resize", Action{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}}, StateReady},
		{"move", Action{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: project("org-1-0")}, StateReady},
		{"join recovery", Action{Kind: KindScaleOut, Node: "gru-1-db-4", Recovery: true}, StateJoining},
		{"drain recovery", Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, StateDraining},
		{"termination recovery", Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, StateDrained},
	} {
		for _, change := range []string{"instance", "incarnation"} {
			for _, replacement := range []int{0, 1, 3} {
				t.Run(test.name+"/"+change+"/"+NodeName("gru-1", replacement+1), func(t *testing.T) {
					cell := newFakeCell(4, small, 2, 150)
					cell.state["gru-1-db-4"] = test.state
					s := newSim(t, testPolicy(), cell, time.Minute)
					original := s.observe()
					if original.Replicas == nil {
						t.Fatal("baseline replica inventory unavailable")
					}
					cache := &restartCache{fakeCell: cell, freezeAll: true, before: map[string]NodePressure{}}
					for _, node := range original.Nodes {
						cache.before[node.Name] = *node.Pressure
					}
					s.controller.config.Source = cache
					if change == "instance" {
						cell.instances[replacement].ID = "replacement-ocid"
					}
					s.now = s.now.Add(time.Second)
					discovered := s.now
					s.observe() // Discover and fence the replacement before supplying evidence.
					pressure := cache.before[original.Nodes[replacement].Name]
					pressure.InstanceID = cell.instances[replacement].ID
					cell.process[pressure.Node]++
					pressure.ProcessID = entityid.Derive("test-process", pressure.Node+"-p2")
					if change == "incarnation" {
						pressure.SampledAt = s.now
						cache.before[pressure.Node] = pressure
						s.observe() // Discover the same-OCI process transition.
					}
					pressure.SampledAt = discovered.Add(MaxPressureClockSkew + time.Second)
					cache.before[pressure.Node] = pressure
					// New-process pressure and placement both clear their fences, so
					// only the ORIGINAL action's identities may refuse the mutation.
					current := s.observe()
					if current.Replicas == nil || !current.Replicas.SampledAt.After(original.Replicas.SampledAt) ||
						!current.Replicas.SampledAt.After(s.controller.replicasAfter) || validReplicaInventory(current) != nil {
						t.Fatal("replacement did not receive strictly newer safe inventory")
					}
					for i, node := range current.Nodes {
						if i == replacement {
							if node.Pressure == nil || !reflect.DeepEqual(*node.Pressure, pressure) {
								t.Fatal("replacement did not receive fresh new-process pressure")
							}
						} else if !reflect.DeepEqual(node.Pressure, original.Nodes[i].Pressure) {
							t.Fatal("replacement test changed cached readiness or process evidence")
						}
					}
					assertIdentityInvalidated(t, s.controller, original.Nodes[replacement].Identity())
					if change == "incarnation" && s.controller.retiredInstances[NodeIdentity{Name: pressure.Node, InstanceID: pressure.InstanceID}] {
						t.Fatal("incarnation-only replacement retired the still-current OCI instance")
					}
					err := s.controller.apply(t.Context(), original, test.action)
					requireIdentityFailure(t, err)
					if calls := cell.callLog(); len(calls) != 0 {
						t.Fatalf("acted on replacement despite safe inventory: %v", calls)
					}
				})
			}
		}
	}
}

func TestScaleOutIdentityReplacementAfterLaunchBlocksJoin(t *testing.T) {
	for _, replacement := range []int{0, 3} {
		t.Run(NodeName("gru-1", replacement+1), func(t *testing.T) {
			cell := newFakeCell(3, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			cell.after = map[string]func(string){"launch": func(string) {
				cell.instances[replacement].ID = "replacement-ocid"
			}}
			err := s.controller.apply(t.Context(), original, Action{Kind: KindScaleOut, Node: "gru-1-db-4", To: small})
			requireIdentityFailure(t, err)
			if calls := cell.callLog(); !slices.Equal(calls, []string{"launch gru-1-db-4 2 OCPU/12 GB"}) {
				t.Fatalf("joined a replacement after launch: %v", calls)
			}
		})
	}
}

func TestActionIdentityRecheckRejectsReplacementDuringInventoryRead(t *testing.T) {
	for _, action := range []Action{
		{Kind: KindScaleOut, Node: "gru-1-db-5", To: small},
		{Kind: KindScaleIn, Node: "gru-1-db-4"},
		{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}},
		{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: project("org-1-0")},
	} {
		t.Run(string(action.Kind), func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			s.now = s.now.Add(time.Second)
			cell.replicas = func() (ReplicaSnapshot, error) {
				cell.instances[0].ID = "replacement-ocid"
				return safeReplicaSnapshot(s.now, cell), nil
			}
			err := s.controller.apply(t.Context(), original, action)
			requireIdentityFailure(t, err)
			if len(cell.callLog()) != 0 || s.controller.lastReplicas != nil ||
				!s.controller.retiredInstances[NodeIdentity{Name: original.Nodes[0].Name, InstanceID: original.Nodes[0].ID}] {
				t.Fatalf("fresh inventory hid replacement during recheck: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestScaleInIdentityReplacementDuringDrainBlocksTerminate(t *testing.T) {
	for _, replacement := range []int{0, 3} {
		t.Run(NodeName("gru-1", replacement+1), func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			cell.after = map[string]func(string){"drain": func(string) {
				cell.instances[replacement].ID = "replacement-ocid"
			}}
			err := s.controller.apply(t.Context(), original, Action{Kind: KindScaleIn, Node: "gru-1-db-4"})
			requireIdentityFailure(t, err)
			if calls := cell.callLog(); !slices.Equal(calls, []string{"drain gru-1-db-4"}) {
				t.Fatalf("terminated after replacement during drain: %v", calls)
			}
		})
	}
}

func TestRollingResizeIdentityReplacementAfterFirstRestart(t *testing.T) {
	for _, replacement := range []int{0, 1, 3} {
		t.Run(NodeName("gru-1", replacement+1), func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			replaced := false
			s.now = s.now.Add(time.Second)
			cell.replicas = func() (ReplicaSnapshot, error) {
				if !s.now.After(s.controller.replicasAfter) {
					s.now = s.controller.replicasAfter.Add(time.Second)
				}
				if _, _, pending := s.controller.restartFor("gru-1-db-1"); cell.process["gru-1-db-1"] > 1 && !pending && !replaced {
					cell.instances[replacement].ID = "replacement-ocid"
					replaced = true
				}
				return safeReplicaSnapshot(s.now, cell), nil
			}
			err := s.controller.rollingResize(t.Context(), original, Shape{OCPUs: 4, MemoryGB: 24})
			requireIdentityFailure(t, err)
			if !replaced || len(cell.callLog()) != 1 || s.controller.lastReplicas != nil ||
				!s.controller.retiredInstances[NodeIdentity{Name: original.Nodes[replacement].Name, InstanceID: original.Nodes[replacement].ID}] {
				t.Fatalf("replacement after ready restart was missed: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestRollingResizeIdentityReplacementDuringReadinessInvalidatesProgress(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	original := s.observe()
	s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
		if p.Node == "gru-1-db-1" && !s.controller.pendingRestarts[original.Nodes[0].Identity()].after.IsZero() {
			cell.instances[0].ID = "replacement-ocid"
		}
	}}
	err := s.controller.rollingResize(t.Context(), original, Shape{OCPUs: 4, MemoryGB: 24})
	requireIdentityFailure(t, err)
	assertIdentityInvalidated(t, s.controller, original.Nodes[0].Identity())
	if len(cell.callLog()) != 1 || len(s.controller.restartBarriers) != 0 || s.controller.lastReplicas != nil ||
		!s.controller.retiredInstances[NodeIdentity{Name: original.Nodes[0].Name, InstanceID: original.Nodes[0].ID}] {
		t.Fatalf("replacement inherited predecessor restart progress: err=%v calls=%v pending=%v", err, cell.callLog(), s.controller.pendingRestarts)
	}
}

type actionIdentityCloud struct {
	*fakeCell
	launchID       string
	reverse        bool
	afterTerminate func()
	beforeList     func()
	terminatedIDs  []string
	resizedIDs     []string
}

func (c *actionIdentityCloud) List(ctx context.Context) ([]Instance, error) {
	if c.beforeList != nil {
		c.beforeList()
	}
	instances, err := c.fakeCell.List(ctx)
	if c.reverse {
		slices.Reverse(instances)
	}
	return instances, err
}

func (c *actionIdentityCloud) Launch(ctx context.Context, name string, shape Shape) (Instance, error) {
	instance, err := c.fakeCell.Launch(ctx, name, shape)
	if err == nil && c.launchID != "" {
		index := c.find(instance.ID)
		instance.ID = c.launchID
		c.instances[index].ID = instance.ID
	}
	return instance, err
}

func (c *actionIdentityCloud) Resize(ctx context.Context, id string, shape Shape) error {
	c.resizedIDs = append(c.resizedIDs, id)
	return c.fakeCell.Resize(ctx, id, shape)
}

func (c *actionIdentityCloud) Terminate(ctx context.Context, id string) error {
	c.terminatedIDs = append(c.terminatedIDs, id)
	err := c.fakeCell.Terminate(ctx, id)
	if err == nil && c.afterTerminate != nil {
		c.afterTerminate()
	}
	return err
}

type actionIdentityMembers struct {
	Members
	afterJoin func()
}

func (m actionIdentityMembers) Join(ctx context.Context, node NodeIdentity) error {
	err := m.Members.Join(ctx, node)
	if err == nil && m.afterJoin != nil {
		m.afterJoin()
	}
	return err
}

func TestActionIdentityConvergenceDoesNotJournalFalseSuccess(t *testing.T) {
	for _, convergence := range []string{"resize", "termination target", "termination peer", "join"} {
		t.Run(convergence, func(t *testing.T) {
			audit := captureJournal(t)
			policy := testPolicy()
			policy.SustainUpSeconds, policy.SustainDownSeconds = 0, 0
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			cloud := &actionIdentityCloud{fakeCell: cell}
			s.controller.config.Cloud = cloud
			// Stabilize discovery so Tick can act immediately with safe inventory.
			s.observe()
			wantKind, wantCalls := KindScaleIn, 2
			switch convergence {
			case "resize":
				wantKind, wantCalls = KindResize, 4
				cell.coresPerRequest = 1.0 / 150
				cell.onResize = func(node string) {
					if node == "gru-1-db-4" {
						cell.instances[3].ID = "replacement-ocid"
						cell.instances[3].State = "RUNNING"
					}
				}
			case "termination target":
				terminated := cell.instances[3]
				listed := 0
				cloud.afterTerminate = func() {
					terminated.ID = "replacement-ocid"
					cell.instances = append(cell.instances, terminated)
					cloud.beforeList = func() {
						listed++
						if listed > 1 {
							cell.instances = cell.instances[:3]
							cloud.beforeList = nil
						}
					}
				}
			case "termination peer":
				cloud.afterTerminate = func() { cell.instances[0].ID = "replacement-ocid" }
			case "join":
				wantKind = KindScaleOut
				cell.setScale(8)
				s.controller.config.Members = actionIdentityMembers{Members: s.controller.config.Members, afterJoin: func() {
					cell.instances[4].ID = "replacement-ocid"
				}}
			}
			action, err := s.controller.Tick(t.Context())
			requireIdentityFailure(t, err)
			if action.Kind != wantKind || len(cell.callLog()) != wantCalls || s.controller.History().Failures != 1 {
				t.Fatalf("unexpected convergence result: action=%+v history=%+v calls=%v", action, s.controller.History(), cell.callLog())
			}
			failed := false
			for _, decision := range audit.decisions {
				if decision.Status == decisionlog.StatusSucceeded {
					t.Fatal("replacement was journaled as a successful action")
				}
				failed = failed || decision.Status == decisionlog.StatusFailed
			}
			if !failed {
				t.Fatal("failed convergence was not journaled")
			}
		})
	}
}

func TestStableActionIdentitiesCompleteWithReorderedMembership(t *testing.T) {
	for _, test := range []struct {
		name   string
		action Action
		state  NodeState
		calls  int
	}{
		{"launch", Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}, StateReady, 2},
		{"drain", Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, StateReady, 2},
		{"resize", Action{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}}, StateReady, 4},
		{"move", Action{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: project("org-1-0")}, StateReady, 1},
		{"join recovery", Action{Kind: KindScaleOut, Node: "gru-1-db-4", Recovery: true}, StateJoining, 1},
		{"termination recovery", Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, StateDrained, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			cell.state["gru-1-db-4"] = test.state
			for i := range cell.instances {
				cell.instances[i].ID = "original-" + cell.instances[i].Name
			}
			s := newSim(t, testPolicy(), cell, time.Minute)
			if test.action.Kind == KindRebalance {
				// A normal autonomous move must relieve an attributed hotspot.
				s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
					if p.Node == test.action.Node {
						p.CPUUtil = 0.9
					}
				}}
			}
			original := s.observe()
			cloud := &actionIdentityCloud{fakeCell: cell, launchID: "actual-launch-result-ocid", reverse: true}
			s.controller.config.Cloud = cloud
			if err := s.controller.apply(t.Context(), original, test.action); err != nil || len(cell.callLog()) != test.calls {
				t.Fatalf("stable IDs/order prevented normal action: err=%v calls=%v", err, cell.callLog())
			}
			if test.action.Kind == KindScaleIn && !slices.Equal(cloud.terminatedIDs, []string{original.Nodes[3].ID}) {
				t.Fatalf("termination used another observation's ID: %v", cloud.terminatedIDs)
			}
			if test.action.Kind == KindResize {
				for i, id := range cloud.resizedIDs {
					if id != original.Nodes[i].ID {
						t.Fatalf("resize used another observation's ID: %v", cloud.resizedIDs)
					}
				}
			}
		})
	}
}

func TestActionRecheckRejectsShapeChangedByFinalOCIRead(t *testing.T) {
	for _, action := range []Action{
		{Kind: KindScaleOut, Node: "gru-1-db-5", To: small},
		{Kind: KindScaleIn, Node: "gru-1-db-4"},
		{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}},
		{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: project("org-1-0")},
	} {
		for _, resource := range []string{"CPU", "memory", "both nodes"} {
			t.Run(string(action.Kind)+"/"+resource, func(t *testing.T) {
				cell := newFakeCell(4, small, 2, 100)
				s := newSim(t, testPolicy(), cell, time.Minute)
				if action.Kind == KindRebalance {
					s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
						if p.Node == "gru-1-db-1" {
							p.CPUUtil = 0.9
						}
					}}
				}
				original := s.observe()
				lists := 0
				s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
					lists++
					if lists == 3 {
						if resource != "memory" {
							cell.instances[1].Shape.OCPUs = 1
						} else {
							cell.instances[1].Shape.MemoryGB = 6
						}
						if resource == "both nodes" {
							cell.instances[2].Shape.MemoryGB = 6
						}
					}
				}}
				err := s.controller.apply(t.Context(), original, action)
				if lists != 3 || err == nil || !strings.Contains(err.Error(), "shape changed") || len(cell.callLog()) != 0 {
					t.Fatalf("final OCI shape bypassed evidence: lists=%d err=%v calls=%v", lists, err, cell.callLog())
				}
				for i := 1; i <= 2; i++ {
					if i == 2 && resource != "both nodes" {
						continue
					}
					node := original.Nodes[i]
					_, cached := s.controller.lastPressure[node.Identity()]
					if cached || s.controller.lastReplicas != nil || !s.controller.pressureAfter[node.Name].Equal(s.now.Add(MaxPressureClockSkew)) {
						t.Fatalf("shape refusal retained old evidence for %s: cached=%t pressure floor=%s", node.Name, cached, s.controller.pressureAfter[node.Name])
					}
				}
			})
		}
	}
}

func TestActionRecheckRejectsPressureAgedByIdentityRead(t *testing.T) {
	for _, action := range []Action{
		{Kind: KindScaleOut, Node: "gru-1-db-5", To: small},
		{Kind: KindScaleIn, Node: "gru-1-db-4"},
		{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}},
		{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: project("org-1-0")},
	} {
		t.Run(string(action.Kind), func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			lists := 0
			s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
				lists++
				if lists == 3 {
					cell.advance(MaxPressureAge + time.Second)
				}
			}}
			err := s.controller.apply(t.Context(), original, action)
			if err == nil || !strings.Contains(err.Error(), "not ready") || len(cell.callLog()) != 0 {
				t.Fatalf("expired pressure authorized %s: err=%v calls=%v", action.Kind, err, cell.callLog())
			}
		})
	}
}

func TestActionConvergenceRejectsEvidenceAgedByIdentityRead(t *testing.T) {
	for _, evidence := range []string{"ready", "drained", "restart", "replicas"} {
		t.Run(evidence, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			s.controller.config.ReadyTimeout = waitTimeout
			stamp := s.now
			lists := 0
			finalRead := 4 // Two OCI reads bracket each pressure probe.
			if evidence == "replicas" {
				finalRead = 5 // Replica convergence also observes the whole cell.
			}
			readEvidence := false
			s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
				lists++
				if lists == finalRead {
					cell.advance(MaxPressureAge + time.Second)
				}
			}}
			var err error
			if evidence == "replicas" {
				snapshot := safeReplicaSnapshot(stamp, cell)
				cell.replicas = func() (ReplicaSnapshot, error) {
					readEvidence = true
					return snapshot, nil
				}
				err = s.controller.waitReplicas(t.Context(), names(original.Nodes), original)
			} else {
				state := StateReady
				if evidence == "drained" {
					state = StateDrained
				}
				cached := *original.Nodes[3].Pressure
				cached.SampledAt, cached.State = stamp, state
				s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
					if p.Node == cached.Node {
						readEvidence = true
						*p = cached
					}
				}}
				if evidence == "restart" {
					s.controller.pendingRestarts[original.Nodes[3].Identity()] = restartFence{shape: small, process: "old-process", after: stamp.Add(-time.Second)}
				}
				err = s.controller.waitNode(t.Context(), identities(original.Nodes), "gru-1-db-4", func(p NodePressure) bool { return p.State == state })
				if evidence == "restart" && len(s.controller.pendingRestarts) != 1 {
					t.Fatal("aged readiness released the restart fence")
				}
			}
			if err == nil || !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "not ready") ||
				!readEvidence || lists < finalRead || len(cell.callLog()) != 0 {
				t.Fatalf("aged %s evidence completed convergence: err=%v calls=%v", evidence, err, cell.callLog())
			}
		})
	}
}
