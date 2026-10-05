package cellscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"
)

type identityPhaseSource struct {
	*fakeCell
	after func(string)
}

func (s identityPhaseSource) Pressure(ctx context.Context, node string) (NodePressure, error) {
	p, err := s.fakeCell.Pressure(ctx, node)
	if err == nil && s.after != nil {
		s.after(node)
	}
	return p, err
}

// Each phase runs the real action, replaces every existing node by both
// possible identity changes, and checks the exact boundary of permitted
// effects. The two resize phases before binding intentionally permit the
// target's one fresh incarnation after same-OCID/shape convergence.
func TestNodeIdentityReplacementAtEveryControllerPhase(t *testing.T) {
	big := Shape{OCPUs: 4, MemoryGB: 24}
	phases := []struct {
		name       string
		action     Action
		state      NodeState
		boundary   string
		maxEffects int
		controlled bool
	}{
		{"observation pressure RPC", Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}, StateReady, "observation pressure", 0, false},
		{"before launch", Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}, StateReady, "before", 0, false},
		{"before drain", Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, StateReady, "before", 0, false},
		{"before resize", Action{Kind: KindResize, To: big}, StateReady, "before", 0, false},
		{"before move", Action{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: "org-1-0"}, StateReady, "before", 0, false},
		{"before join recovery", Action{Kind: KindScaleOut, Node: "gru-1-db-4", Recovery: true}, StateJoining, "before", 0, false},
		{"before drain recovery", Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, StateDraining, "before", 0, false},
		{"before termination recovery", Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, StateDrained, "before", 0, false},
		{"startup readiness", Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}, StateReady, "launch", 1, false},
		{"joined readiness", Action{Kind: KindScaleOut, Node: "gru-1-db-4", Recovery: true}, StateJoining, "join", 1, false},
		{"drained readiness", Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, StateReady, "drain", 1, false},
		{"resize OCI convergence", Action{Kind: KindResize, To: big}, StateReady, "resize", 1, true},
		{"resize readiness RPC", Action{Kind: KindResize, To: big}, StateReady, "resize pressure", 1, false},
		{"resize replica convergence", Action{Kind: KindResize, To: big}, StateReady, "resize replicas", 1, false},
		{"termination completion", Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, StateReady, "termination", 2, false},
		{"drain replica convergence", Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, StateReady, "drain replicas", 1, false},
	}
	for _, phase := range phases {
		for replacement := range 4 {
			for _, change := range []string{"OCI replacement", "incarnation change"} {
				t.Run(fmt.Sprintf("%s/%s/%s", phase.name, NodeName("gru-1", replacement+1), change), func(t *testing.T) {
					cell := newFakeCell(4, small, 2, 150)
					cell.state["gru-1-db-4"] = phase.state
					s := newSim(t, testPolicy(), cell, time.Minute)
					s.controller.config.ReadyTimeout = 40 * time.Millisecond
					original := s.observe()
					old := original.Nodes[replacement].Identity()
					oldPressure := *original.Nodes[replacement].Pressure
					oldInventory := *original.Replicas
					replaced := false
					var invalidated NodeIdentity
					inject := func() {
						if replaced {
							return
						}
						replaced = true
						invalidated = s.controller.activeIdentities[old.Name]
						if phase.boundary == "termination" && replacement == 3 {
							// The name reappears while OCI termination is completing.
							cell.instances = append(cell.instances, Instance{Name: old.Name, ID: old.InstanceID, Shape: small, State: "RUNNING"})
						}
						if change == "OCI replacement" {
							cell.instances[replacement].ID += "-replacement"
						}
						cell.process[old.Name] += 100
					}
					cell.after = map[string]func(string){}
					switch phase.boundary {
					case "before":
						inject()
					case "observation pressure":
						s.controller.config.Source = identityPhaseSource{cell, func(string) { inject() }}
					case "termination":
						s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, afterTerminate: inject}
					case "launch", "drain":
						cell.after[phase.boundary] = func(string) { inject() }
					case "join":
						s.controller.config.Source = identityPhaseSource{cell, func(string) {
							if len(cell.callLog()) == 1 {
								inject()
							}
						}}
					case "resize":
						cell.onResize = func(string) { inject() }
					case "resize pressure":
						s.controller.config.Source = identityPhaseSource{cell, func(node string) {
							if node == "gru-1-db-1" && len(cell.callLog()) == 1 {
								_, fence, pending := s.controller.restartFor(node)
								if pending && !fence.after.IsZero() {
									inject()
								}
							}
						}}
					case "resize replicas", "drain replicas":
						cell.replicas = func() (ReplicaSnapshot, error) {
							if len(cell.callLog()) == 1 {
								if phase.boundary == "drain replicas" || s.controller.activeIdentities["gru-1-db-1"].Incarnation != original.Nodes[0].Identity().Incarnation {
									inject()
								}
							}
							// Return plausible, freshly dated predecessor inventory:
							// its full identities must prevent it from authorizing effects.
							snapshot := oldInventory
							snapshot.SampledAt = s.now
							return snapshot, nil
						}
					}
					err := s.controller.apply(t.Context(), original, phase.action)
					permittedRestart := phase.controlled && change == "incarnation change" && replacement == 0
					if permittedRestart && (err != nil || len(cell.callLog()) != 4) {
						t.Fatalf("authorized fresh controlled restart did not converge: err=%v calls=%v", err, cell.callLog())
					}
					if !replaced {
						t.Fatalf("controller never reached phase: err=%v calls=%v", err, cell.callLog())
					}
					limit := phase.maxEffects
					if permittedRestart {
						limit = 4
					}
					if len(cell.callLog()) > limit || !permittedRestart && err == nil {
						t.Fatalf("replacement authorized an effect: err=%v calls=%v limit=%d", err, cell.callLog(), limit)
					}
					// Discover any identity changed just after the final RPC, then
					// verify that operational predecessor state is entirely gone.
					cell.replicas = nil
					s.controller.config.Source = cell
					_, _ = s.controller.observe(t.Context())
					if _, exists := s.controller.lastPressure[invalidated]; exists {
						t.Fatal("predecessor pressure survived identity invalidation")
					}
					if _, exists := s.controller.pendingRestarts[invalidated]; exists {
						t.Fatal("predecessor resize progress survived identity invalidation")
					}
					oldPressure.SampledAt = s.now
					oldInventory.SampledAt = s.now
					if s.controller.retainPressure(old.Name, oldPressure) || s.controller.replicasUsable(oldInventory) {
						t.Fatal("freshly dated predecessor telemetry or inventory authorized the successor")
					}
					// Fresh successor readiness and full-identity inventory recover
					// without a coordinator or live OCI. Release an ambiguous resize
					// only after the fake OCI instance actually reaches its shape.
					for id, fence := range s.controller.restartBarriers {
						if index := slices.IndexFunc(cell.instances, func(i Instance) bool { return i.Name == id.Name && i.ID == id.InstanceID }); index >= 0 {
							cell.instances[index].Shape = fence.shape
							cell.instances[index].State = "RUNNING"
						}
					}
					cell.state[old.Name] = StateReady
					s.now = s.now.Add(20 * time.Second)
					_, _ = s.controller.observe(t.Context())
					s.now = s.now.Add(20 * time.Second)
					current, recoveryErr := s.controller.observe(t.Context())
					index := slices.IndexFunc(current.Nodes, func(n Node) bool { return n.Name == old.Name })
					if recoveryErr != nil || index < 0 || current.Nodes[index].Pressure == nil || current.Replicas == nil {
						t.Fatalf("safe successor did not recover: err=%v state=%+v barriers=%v", recoveryErr, current, s.controller.restartBarriers)
					}
				})
			}
		}
	}
}

// The reusable name can route to a successor after the controller's last
// check. The mutation receiver must enforce both complete identity tuples.
func TestMembershipMutationIdentityPreconditionAtDelivery(t *testing.T) {
	from := NodeIdentity{Name: "gru-1-db-1", InstanceID: "ocid-source", Incarnation: "source-p1"}
	to := NodeIdentity{Name: "gru-1-db-2", InstanceID: "ocid-target", Incarnation: "target-p1"}
	for _, operation := range []string{"join", "drain", "move"} {
		for _, endpoint := range []string{"source", "target"} {
			if endpoint == "target" && operation != "move" {
				continue
			}
			for _, change := range []string{"OCI replacement", "incarnation change"} {
				t.Run(operation+"/"+endpoint+"/"+change, func(t *testing.T) {
					mutated := false
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						var body struct {
							Expected NodeIdentity `json:"expected"`
							Target   NodeIdentity `json:"expected_target"`
						}
						if json.NewDecoder(r.Body).Decode(&body) != nil || body.Expected != from || operation == "move" && body.Target != to {
							t.Error("mutation omitted its original full identity preconditions")
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						currentFrom, currentTo := from, to
						current := &currentFrom
						if endpoint == "target" {
							current = &currentTo
						}
						if change == "OCI replacement" {
							current.InstanceID += "-replacement"
						} else {
							current.Incarnation += "-reboot"
						}
						if body.Expected != currentFrom || operation == "move" && body.Target != currentTo {
							w.WriteHeader(http.StatusConflict)
							return
						}
						mutated = true
						w.WriteHeader(http.StatusAccepted)
					}))
					defer server.Close()
					members := HTTPMembers{Client: server.Client(), Endpoint: func(string) string { return server.URL }}
					var err error
					switch operation {
					case "join":
						err = members.Join(t.Context(), from)
					case "drain":
						err = members.Drain(t.Context(), from)
					case "move":
						err = members.MoveTenant(t.Context(), "org", from, to)
					}
					if err == nil || mutated {
						t.Fatalf("delivery to a successor performed the mutation: err=%v", err)
					}
				})
			}
		}
	}
}

func TestPressureRequiresIndependentOCIIdentity(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	pressure, err := cell.Pressure(t.Context(), "gru-1-db-1")
	if err != nil {
		t.Fatal(err)
	}
	if s.controller.retainPressure(pressure.Node, pressure) || len(s.controller.activeIdentities) != 0 || len(s.controller.lastPressure) != 0 {
		t.Fatal("pressure established its own OCI identity")
	}
	s.controller.trackPressureIdentities(cell.instances)
	if !s.controller.retainPressure(pressure.Node, pressure) {
		t.Fatal("independently listed identity could not accept fresh first-incarnation pressure")
	}
}

func TestIdentityTransitionInvalidatesAllOperationalState(t *testing.T) {
	for replacement := range 4 {
		for _, change := range []string{"OCI replacement", "incarnation change"} {
			t.Run(NodeName("gru-1", replacement+1)+"/"+change, func(t *testing.T) {
				cell := newFakeCell(4, small, 2, 150)
				s := newSim(t, testPolicy(), cell, time.Minute)
				original := s.observe()
				old := original.Nodes[replacement].Identity()
				pressure := *original.Nodes[replacement].Pressure
				floor := s.now.Add(MaxPressureClockSkew)
				s.controller.pressureAfter[old.Name] = floor
				s.controller.pendingRestarts[old] = restartFence{shape: small, process: old.Incarnation}
				s.controller.history = History{Want: string(KindScaleIn), WantSince: s.now, LastAction: s.now, Failures: 2, Paused: true}
				history := s.controller.History()
				s.now = s.now.Add(-time.Second)
				next := old
				next.Incarnation += "-replacement"
				if change == "OCI replacement" {
					next.InstanceID += "-replacement"
				}
				s.controller.transitionIdentity(next, s.now.Add(MaxPressureClockSkew))
				_, pressureSurvived := s.controller.lastPressure[old]
				_, progressSurvived := s.controller.pendingRestarts[old]
				if pressureSurvived || progressSurvived || len(s.controller.lastPressure) != 3 || s.controller.lastReplicas != nil {
					t.Fatal("transition retained predecessor operational state or erased peer pressure")
				}
				if s.controller.pressureAfter[old.Name].Before(floor) || s.controller.replicasAfter.Before(original.Replicas.SampledAt) {
					t.Fatal("clock regression lowered a refusal floor")
				}
				history.Want, history.WantSince = "", time.Time{}
				if !reflect.DeepEqual(s.controller.History(), history) {
					t.Fatal("transition changed cooldown, failures, or pause state")
				}
				pressure.SampledAt = s.now.Add(time.Second)
				if s.controller.retainPressure(old.Name, pressure) {
					t.Fatal("fresh timestamp revived the retired incarnation")
				}
			})
		}
	}
}

func TestRetiredIncarnationCannotResolveConflictingTimestamp(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	original := s.observe()
	old := *original.Nodes[0].Pressure
	s.now = s.now.Add(10 * time.Second)
	successor := old
	successor.ProcessID += "-reboot"
	successor.SampledAt = s.now
	s.controller.transitionIdentity(successor.Identity(), time.Time{})
	if !s.controller.retainPressure(successor.Node, successor) {
		t.Fatal("fresh successor setup rejected")
	}
	s.now = s.now.Add(time.Second)
	old.SampledAt, successor.SampledAt = s.now, s.now
	if s.controller.retainPressure(old.Node, old) || s.controller.retainPressure(successor.Node, successor) {
		t.Fatal("equal-timestamp evidence bypassed the retired-incarnation refusal floor")
	}
	s.now = s.now.Add(time.Second)
	successor.SampledAt = s.now
	if !s.controller.retainPressure(successor.Node, successor) {
		t.Fatal("strictly newer successor pressure could not recover")
	}
}

func TestUnseenIncarnationCannotRetireCurrentWithObsoleteEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset time.Duration
		floor  time.Duration
	}{
		{"before high water", -time.Second, 0},
		{"equal high water", 0, 0},
		{"before refusal floor", time.Second, 2 * time.Second},
		{"equal refusal floor", 2 * time.Second, 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			current := *s.observe().Nodes[0].Pressure
			if test.floor != 0 {
				s.controller.pressureAfter[current.Node] = current.SampledAt.Add(test.floor)
			}
			obsolete := current
			obsolete.ProcessID = "unseen-predecessor"
			obsolete.SampledAt = current.SampledAt.Add(test.offset)
			if s.controller.retainPressure(obsolete.Node, obsolete) ||
				s.controller.activeIdentities[current.Node] != current.Identity() ||
				s.controller.retiredIncarnations[NodeIdentity{Name: current.Node, Incarnation: current.ProcessID}] {
				t.Fatal("obsolete evidence accepted or retired the running identity")
			}
			if test.offset == 0 && s.controller.retainPressure(current.Node, current) {
				t.Fatal("equal-timestamp contradiction accepted cached current readiness")
			}
			s.now = s.now.Add(20 * time.Second)
			recovered := s.observe()
			if !recovered.Nodes[0].ready() || recovered.Nodes[0].Identity() != current.Identity() ||
				recovered.Replicas == nil || len(cell.callLog()) != 0 {
				t.Fatal("fresh running-process evidence could not recover safely")
			}
		})
	}
}
