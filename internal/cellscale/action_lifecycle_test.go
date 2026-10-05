package cellscale

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// Override OCI's lifecycle independently of cached TerraBase responses and
// the fake's automatic restart progression, without changing instance IDs.
type actionLifecycleCloud struct {
	*actionIdentityCloud
	states map[string]string
}

func (c *actionLifecycleCloud) List(ctx context.Context) ([]Instance, error) {
	instances, err := c.actionIdentityCloud.List(ctx)
	for i := range instances {
		if state, ok := c.states[instances[i].Name]; ok {
			instances[i].State = state
		}
	}
	return instances, err
}

func requireLifecycleFailure(t *testing.T, err error, node, lifecycle string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "node "+node+" OCI lifecycle "+lifecycle+" is not RUNNING") {
		t.Fatalf("expected same-ID OCI lifecycle refusal for %s/%s, got %v", node, lifecycle, err)
	}
}

func assertRestartRefusal(t *testing.T, c *Controller, old NodeIdentity, fence restartFence) {
	t.Helper()
	if c.activeIdentities[old.Name] != old {
		assertIdentityInvalidated(t, c, old)
		if barrier, found := c.restartBarriers[old]; !found || barrier != fence {
			t.Fatalf("unsafe recovery lost predecessor refusal barrier: %v", c.restartBarriers)
		}
	} else if pending, found := c.pendingRestarts[old]; !found || pending != fence {
		t.Fatalf("unsafe recovery lost pending restart fence: %v", c.pendingRestarts)
	}
}

func TestActionLifecycleRecheckRejectsSameIDDowntimeDuringEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		action Action
		state  NodeState
		nodes  []string
	}{
		{"launch", Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}, StateReady, []string{"gru-1-db-1", "gru-1-db-4"}},
		{"drain", Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, StateReady, []string{"gru-1-db-1", "gru-1-db-4"}},
		{"resize", Action{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}}, StateReady, []string{"gru-1-db-2", "gru-1-db-1"}},
		{"move", Action{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: "org-1-0"}, StateReady, []string{"gru-1-db-3", "gru-1-db-1", "gru-1-db-2"}},
		{"join recovery", Action{Kind: KindScaleOut, Node: "gru-1-db-4", Recovery: true}, StateJoining, []string{"gru-1-db-1", "gru-1-db-4"}},
		{"drain recovery", Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, StateDraining, []string{"gru-1-db-1", "gru-1-db-4"}},
		{"termination recovery", Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, StateDrained, []string{"gru-1-db-1", "gru-1-db-4"}},
	} {
		for _, read := range []string{"pressure", "replicas"} {
			for _, lifecycle := range []string{"STOPPING", "STOPPED"} {
				for _, node := range test.nodes {
					t.Run(test.name+"/"+read+"/"+lifecycle+"/"+node, func(t *testing.T) {
						cell := newFakeCell(4, small, 2, 150)
						cell.state["gru-1-db-4"] = test.state
						s := newSim(t, testPolicy(), cell, time.Minute)
						original := s.observe()
						want := identities(original.Nodes)
						cloud := &actionLifecycleCloud{actionIdentityCloud: &actionIdentityCloud{fakeCell: cell}, states: map[string]string{}}
						s.controller.config.Cloud = cloud
						s.controller.config.ReadyTimeout = 20 * time.Millisecond
						s.now = s.now.Add(time.Second)
						if read == "pressure" {
							s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
								if p.Node == "gru-1-db-4" {
									cloud.states[node] = lifecycle
								}
							}}
						}
						cell.replicas = func() (ReplicaSnapshot, error) {
							if read == "replicas" {
								cloud.states[node] = lifecycle
							}
							return safeReplicaSnapshot(s.now, cell), nil
						}
						err := s.controller.apply(t.Context(), original, test.action)
						beforeRecheck := test.name == "join recovery" && read == "pressure"
						if beforeRecheck && node == test.action.Node {
							if !errors.Is(err, context.DeadlineExceeded) {
								t.Fatalf("down joining target authorized admission: %v", err)
							}
						} else {
							requireLifecycleFailure(t, err, node, lifecycle)
						}
						if len(cell.callLog()) != 0 || !maps.Equal(want, identities(original.Nodes)) ||
							!maps.Equal(want, s.controller.lastMembership) ||
							!beforeRecheck && !s.controller.lastReplicas.SampledAt.After(original.Replicas.SampledAt) ||
							!s.controller.replicasAfter.Equal(s.now.Add(MaxPressureClockSkew)) {
							t.Fatalf("lifecycle read lost its fence/identity/high-water evidence: err=%v calls=%v", err, cell.callLog())
						}
					})
				}
			}
		}
	}
}

func TestActionLifecycleConvergenceRejectsSameIDDowntimeDuringEvidence(t *testing.T) {
	for _, evidence := range []string{"ready", "drained", "restart", "replicas"} {
		for _, node := range []string{"gru-1-db-1", "gru-1-db-4"} {
			for _, lifecycle := range []string{"STOPPING", "STOPPED"} {
				t.Run(evidence+"/"+node+"/"+lifecycle, func(t *testing.T) {
					// Keep the 20ms convergence deadline independent of runner load.
					synctest.Test(t, func(t *testing.T) {
						cell := newFakeCell(4, small, 2, 150)
						s := newSim(t, testPolicy(), cell, time.Minute)
						original := s.observe()
						s.now = s.now.Add(time.Second)
						s.controller.config.ReadyTimeout = 20 * time.Millisecond
						cloud := &actionLifecycleCloud{actionIdentityCloud: &actionIdentityCloud{fakeCell: cell}, states: map[string]string{}}
						s.controller.config.Cloud = cloud
						fence := restartFence{shape: small, process: original.Nodes[3].Pressure.ProcessID, after: s.now.Add(-time.Second)}
						var err error
						if evidence == "replicas" {
							cell.replicas = func() (ReplicaSnapshot, error) {
								cloud.states[node] = lifecycle
								return safeReplicaSnapshot(s.now, cell), nil
							}
							err = s.controller.waitReplicas(t.Context(), names(original.Nodes), original)
						} else {
							state := StateReady
							if evidence == "drained" {
								state = StateDrained
							}
							cell.state["gru-1-db-4"] = state
							if evidence == "restart" {
								cell.process["gru-1-db-4"]++
								s.controller.pendingRestarts[original.Nodes[3].Identity()] = fence
							}
							s.controller.config.Source = changedLoad{cell, func(*NodePressure) { cloud.states[node] = lifecycle }}
							err = s.controller.waitNode(t.Context(), identities(original.Nodes), "gru-1-db-4", func(p NodePressure) bool { return p.State == state })
						}
						if node == "gru-1-db-4" && evidence != "replicas" {
							if !errors.Is(err, context.DeadlineExceeded) {
								t.Fatalf("down controlled target completed readiness instead of waiting: %v", err)
							}
						} else {
							requireLifecycleFailure(t, err, node, lifecycle)
						}
						if evidence == "restart" {
							assertRestartRefusal(t, s.controller, original.Nodes[3].Identity(), fence)
						}
						if len(cell.callLog()) != 0 {
							t.Fatalf("convergence mutated the cell: %v", cell.callLog())
						}
					})
				})
			}
		}
	}
}

func TestObserveLifecycleRecoveryRetainsRestartFenceDuringEvidence(t *testing.T) {
	for _, read := range []string{"pressure", "replicas"} {
		for _, node := range []string{"gru-1-db-1", "gru-1-db-4"} {
			for _, lifecycle := range []string{"STOPPING", "STOPPED"} {
				t.Run(read+"/"+node+"/"+lifecycle, func(t *testing.T) {
					cell := newFakeCell(4, small, 2, 150)
					s := newSim(t, testPolicy(), cell, time.Minute)
					original := s.observe()
					s.now = s.now.Add(time.Second)
					fence := restartFence{shape: small, process: original.Nodes[0].Pressure.ProcessID, after: s.now.Add(-time.Second)}
					s.controller.pendingRestarts[original.Nodes[0].Identity()] = fence
					cell.process["gru-1-db-1"]++
					cloud := &actionLifecycleCloud{actionIdentityCloud: &actionIdentityCloud{fakeCell: cell}, states: map[string]string{}}
					s.controller.config.Cloud = cloud
					if read == "pressure" {
						s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
							if p.Node == "gru-1-db-4" {
								cloud.states[node] = lifecycle
							}
						}}
					}
					cell.replicas = func() (ReplicaSnapshot, error) {
						assertRestartRefusal(t, s.controller, original.Nodes[0].Identity(), fence)
						if !s.now.After(s.controller.replicasAfter) {
							s.now = s.controller.replicasAfter.Add(time.Second)
						}
						if read == "replicas" {
							cloud.states[node] = lifecycle
						}
						return safeReplicaSnapshot(s.now, cell), nil
					}
					_, err := s.controller.observe(t.Context())
					requireLifecycleFailure(t, err, node, lifecycle)
					assertRestartRefusal(t, s.controller, original.Nodes[0].Identity(), fence)
					if s.controller.lastPressure[s.controller.activeIdentities["gru-1-db-1"]].ProcessID == fence.process ||
						s.controller.lastReplicas == nil || !s.controller.lastReplicas.SampledAt.After(original.Replicas.SampledAt) {
						t.Fatalf("unsafe recovery lost pending or high-water evidence: %v", s.controller.pendingRestarts)
					}
					// The same IDs can recover once all members run and evidence is newer.
					clear(cloud.states)
					cell.replicas = nil
					s.controller.config.Source = cell
					s.now = s.now.Add(MaxPressureClockSkew + time.Second)
					state := s.observe()
					if len(s.controller.pendingRestarts) != 0 || len(s.controller.restartBarriers) != 0 || state.Replicas == nil || len(cell.callLog()) != 0 {
						t.Fatalf("safe recovery remained fenced: state=%+v pending=%v", state, s.controller.pendingRestarts)
					}
				})
			}
		}
	}
}

func TestObserveLifecycleRecoveryRejectsPressureAgedByFinalOCIRead(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	original := s.observe()
	s.now = s.now.Add(time.Second)
	fence := restartFence{shape: small, process: original.Nodes[0].Pressure.ProcessID, after: s.now.Add(-time.Second)}
	s.controller.pendingRestarts[original.Nodes[0].Identity()] = fence
	cell.process["gru-1-db-1"]++
	lists := 0
	s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
		lists++
		if lists == 3 {
			cell.advance(MaxPressureAge + time.Second)
		}
	}}
	_, err := s.controller.observe(t.Context())
	assertRestartRefusal(t, s.controller, original.Nodes[0].Identity(), fence)
	if lists != 3 || err == nil || !strings.Contains(err.Error(), "not ready") || len(cell.callLog()) != 0 {
		t.Fatalf("aged recovered readiness passed its final OCI read: lists=%d err=%v pending=%v", lists, err, s.controller.pendingRestarts)
	}
}

func TestScaleInLifecycleDowntimeAfterDrainBlocksTermination(t *testing.T) {
	for _, read := range []string{"pressure", "replicas"} {
		for _, node := range []string{"gru-1-db-1", "gru-1-db-4"} {
			t.Run(read+"/"+node, func(t *testing.T) {
				cell := newFakeCell(4, small, 2, 150)
				s := newSim(t, testPolicy(), cell, time.Minute)
				original := s.observe()
				s.now = s.now.Add(time.Second)
				s.controller.config.ReadyTimeout = 20 * time.Millisecond
				cloud := &actionLifecycleCloud{actionIdentityCloud: &actionIdentityCloud{fakeCell: cell}, states: map[string]string{}}
				s.controller.config.Cloud = cloud
				if read == "pressure" {
					s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
						if p.Node == "gru-1-db-4" && p.State == StateDrained {
							cloud.states[node] = "STOPPED"
						}
					}}
				}
				cell.replicas = func() (ReplicaSnapshot, error) {
					if !s.now.After(s.controller.replicasAfter) {
						s.now = s.controller.replicasAfter.Add(time.Second)
					}
					if read == "replicas" && cell.state["gru-1-db-4"] == StateDrained {
						cloud.states[node] = "STOPPED"
					}
					return safeReplicaSnapshot(s.now, cell), nil
				}
				err := s.controller.apply(t.Context(), original, Action{Kind: KindScaleIn, Node: "gru-1-db-4"})
				if read == "pressure" && node == "gru-1-db-4" {
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("down draining target completed convergence: %v", err)
					}
				} else {
					requireLifecycleFailure(t, err, node, "STOPPED")
				}
				if calls := cell.callLog(); !slices.Equal(calls, []string{"drain gru-1-db-4"}) {
					t.Fatalf("terminated with a down member after completed drain: %v", calls)
				}
			})
		}
	}
}

func TestRollingResizeLifecycleDowntimeDuringReplicaConvergenceBlocksNextRestart(t *testing.T) {
	for _, node := range []string{"gru-1-db-1", "gru-1-db-2"} {
		t.Run(node, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			s.now = s.now.Add(time.Second)
			cloud := &actionLifecycleCloud{actionIdentityCloud: &actionIdentityCloud{fakeCell: cell}, states: map[string]string{}}
			s.controller.config.Cloud = cloud
			cell.replicas = func() (ReplicaSnapshot, error) {
				if !s.now.After(s.controller.replicasAfter) {
					s.now = s.controller.replicasAfter.Add(time.Second)
				}
				if len(cell.callLog()) == 1 {
					cloud.states[node] = "STOPPED"
				}
				return safeReplicaSnapshot(s.now, cell), nil
			}
			err := s.controller.rollingResize(t.Context(), original, Shape{OCPUs: 4, MemoryGB: 24})
			requireLifecycleFailure(t, err, node, "STOPPED")
			if calls := cell.callLog(); !slices.Equal(calls, []string{"resize gru-1-db-1 4 OCPU/24 GB"}) {
				t.Fatalf("overlapped restarts after a same-ID lifecycle change: %v", calls)
			}
		})
	}
}

func TestActionLifecycleConvergenceDoesNotJournalFalseSuccess(t *testing.T) {
	for _, convergence := range []string{"resize", "termination", "join"} {
		t.Run(convergence, func(t *testing.T) {
			audit := captureJournal(t)
			policy := testPolicy()
			policy.SustainUpSeconds, policy.SustainDownSeconds = 0, 0
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			cloud := &actionLifecycleCloud{actionIdentityCloud: &actionIdentityCloud{fakeCell: cell}, states: map[string]string{}}
			s.controller.config.Cloud = cloud
			original := s.observe()
			wantKind, wantCalls := KindScaleIn, 2
			switch convergence {
			case "resize":
				wantKind, wantCalls = KindResize, 1
				cell.coresPerRequest = 1.0 / 150
				cell.onResize = func(string) { cloud.states["gru-1-db-2"] = "STOPPED" }
			case "termination":
				cloud.afterTerminate = func() { cloud.states["gru-1-db-2"] = "STOPPED" }
			case "join":
				wantKind = KindScaleOut
				cell.setScale(8)
				s.controller.config.Members = actionIdentityMembers{Members: s.controller.config.Members, afterJoin: func() {
					cloud.states["gru-1-db-2"] = "STOPPED"
				}}
			}
			action, err := s.controller.Tick(t.Context())
			requireLifecycleFailure(t, err, "gru-1-db-2", "STOPPED")
			if action.Kind != wantKind || len(cell.callLog()) != wantCalls || s.controller.History().Failures != 1 {
				t.Fatalf("unsafe convergence continued: action=%+v history=%+v calls=%v", action, s.controller.History(), cell.callLog())
			}
			if convergence == "resize" {
				if fence, pending := s.controller.pendingRestarts[original.Nodes[0].Identity()]; !pending || !fence.after.IsZero() {
					t.Fatalf("down peer released an active restart fence: %v", s.controller.pendingRestarts)
				}
			}
			failed := false
			for _, decision := range audit.decisions {
				if decision.Status == decisionlog.StatusSucceeded {
					t.Fatal("down peer was journaled as successful convergence")
				}
				failed = failed || decision.Status == decisionlog.StatusFailed
			}
			if !failed {
				t.Fatal("unsafe convergence was not journaled as failed")
			}
		})
	}
}

func TestActionLifecycleControlledTargetTransitionsComplete(t *testing.T) {
	for _, transition := range []string{"launch", "resize", "termination"} {
		t.Run(transition, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			cloud := &actionLifecycleCloud{actionIdentityCloud: &actionIdentityCloud{fakeCell: cell}, states: map[string]string{}}
			s.controller.config.Cloud = cloud
			action := Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}
			wantCalls := 2
			listed := 0
			switch transition {
			case "launch":
				cell.after = map[string]func(string){"launch": func(node string) {
					cloud.beforeList = func() {
						states := []string{"PROVISIONING", "STARTING", "RUNNING"}
						cloud.states[node] = states[min(listed, len(states)-1)]
						listed++
					}
				}}
			case "resize":
				action = Action{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}}
				wantCalls = 4
				cell.onResize = func(node string) {
					phase := 0
					cloud.beforeList = func() {
						states := []string{"STOPPING", "STOPPED", "STARTING", "RUNNING"}
						cloud.states[node] = states[min(phase, len(states)-1)]
						phase++
						listed++
					}
				}
			case "termination":
				action = Action{Kind: KindScaleIn, Node: "gru-1-db-4"}
				target := cell.instances[3]
				cloud.afterTerminate = func() {
					target.State = "TERMINATING"
					cell.instances = append(cell.instances, target)
					cloud.beforeList = func() {
						listed++
						if listed == 3 {
							cell.instances = slices.DeleteFunc(cell.instances, func(i Instance) bool { return i.ID == target.ID })
						}
					}
				}
			}
			if err := s.controller.apply(t.Context(), original, action); err != nil || len(cell.callLog()) != wantCalls || listed < 3 {
				t.Fatalf("controlled target lifecycle prevented progress: err=%v listed=%d calls=%v", err, listed, cell.callLog())
			}
		})
	}
}
