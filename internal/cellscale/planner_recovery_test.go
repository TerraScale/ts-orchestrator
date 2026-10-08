package cellscale

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

func TestMemoryOnlyResizeUsesCapacityCooldown(t *testing.T) {
	for _, test := range []struct {
		name    string
		memory  float64
		elapsed time.Duration
		want    Kind
	}{
		{"growth before cooldown", 8, 599 * time.Second, KindHold},
		{"growth after cooldown", 8, 600 * time.Second, KindResize},
		{"shrink before down cooldown", 24, 600 * time.Second, KindHold},
		{"shrink after down cooldown", 24, 1800 * time.Second, KindResize},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal := captureJournal(t)
			policy := testPolicy()
			policy.Shape.MemoryGBPerOCPU = 8
			cell := newFakeCell(3, Shape{OCPUs: 2, MemoryGB: test.memory}, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			s.observe()
			s.controller.history.LastAction = s.now.Add(-test.elapsed)
			action, err := s.controller.Tick(t.Context())
			if err != nil || action.Kind != test.want {
				t.Fatalf("memory convergence used the wrong cooldown: action=%+v err=%v", action, err)
			}
			if test.want == KindHold {
				if action.Reason != ReasonCooldown || len(cell.callLog()) != 0 {
					t.Fatalf("cooldown did not block effects: action=%+v calls=%v", action, cell.callLog())
				}
				return
			}
			if action.Reason != ReasonConvergeShape || action.To != (Shape{OCPUs: 2, MemoryGB: 16}) ||
				action.up() != (test.memory < 16) || len(cell.callLog()) != 3 {
				t.Fatalf("memory convergence did not resize every node: action=%+v calls=%v", action, cell.callLog())
			}
			for _, instance := range cell.instances {
				if instance.Shape != action.To {
					t.Fatalf("node %s did not converge: %+v", instance.Name, instance.Shape)
				}
			}
			kind := decisionlog.KindScaleDown
			if test.memory < 16 {
				kind = decisionlog.KindScaleUp
			}
			if len(journal.decisions) != 2 || journal.decisions[0].Kind != kind || journal.decisions[1].Kind != kind ||
				journal.decisions[1].Status != decisionlog.StatusSucceeded {
				t.Fatalf("memory convergence audited the wrong capacity direction: %+v", journal.decisions)
			}
		})
	}
}

func TestHotspotMovesRequireAttributedDemand(t *testing.T) {
	for _, signal := range []string{"CPU", "requests"} {
		for _, mode := range []string{"zero demand", "empty zero demand", "wrong resource", "useful", "useful tie", "new node"} {
			t.Run(signal+"/"+mode, func(t *testing.T) {
				policy := testPolicy()
				state := observeState(t, policy, newFakeCell(4, small, 2, 100))
				hot := state.Nodes[0].Pressure
				idle := TenantLoad{Project: project("0000000000F6H63RT9R93XQ0MH")}
				useful := TenantLoad{Project: project("useful")}
				if signal == "CPU" {
					hot.CPUUtil, useful.CPUShare = 0.9, 0.6
					if mode == "wrong resource" {
						idle.RequestRate = 100
					}
				} else {
					hot.RequestRate, useful.RequestRate = 2400, 600
					if mode == "wrong resource" {
						idle.CPUShare = 0.2
					}
				}
				hot.TopTenants = []TenantLoad{idle}
				want, tenant := KindResize, ""
				if mode == "useful" || mode == "useful tie" || mode == "new node" {
					hot.TopTenants = append(hot.TopTenants, useful)
					want, tenant = KindRebalance, useful.Project
				}
				// An equally busy tenant reported first moves first.
				if mode == "useful tie" {
					hot.TopTenants[0].CPUShare = useful.CPUShare
					hot.TopTenants[0].RequestRate = useful.RequestRate
					tenant = idle.Project
				}
				if mode == "new node" {
					for _, node := range state.Nodes[1:] {
						if signal == "CPU" {
							node.Pressure.CPUUtil = 0.4
						} else {
							node.Pressure.RequestRate = 1500
						}
					}
					want, tenant = KindScaleOut, ""
				}
				if mode == "empty zero demand" {
					for _, node := range state.Nodes[1:] {
						// No peer fits; zero demand must not justify a new node.
						if signal == "CPU" {
							node.Pressure.RequestRate = 2200
						} else {
							node.Pressure.CPUUtil = 0.75
						}
					}
				}
				action := act(policy, state, History{})
				if action.Kind != want || action.Tenant != tenant || action.Reason != ReasonHotspot {
					t.Fatalf("hotspot selected non-beneficial capacity: %+v, want %s tenant=%s", action, want, tenant)
				}
			})
		}
	}
}

func TestUnattributedHotspotFallsBackToCapacity(t *testing.T) {
	for _, signal := range []string{"memory", "disk"} {
		t.Run(signal, func(t *testing.T) {
			policy := testPolicy()
			state := observeState(t, policy, newFakeCell(4, small, 2, 100))
			hot := state.Nodes[0].Pressure
			hot.TopTenants = []TenantLoad{{Project: project("active"), CPUShare: 0.5, RequestRate: 100}}
			want := KindResize
			if signal == "memory" {
				hot.MemoryUtil = 0.9
			} else {
				hot.DiskUsedBytes = hot.DiskTotalBytes * 9 / 10
				want = KindHold
			}
			if action := act(policy, state, History{}); action.Kind != want {
				t.Fatalf("unattributed hotspot selected a move or tenant-driven launch: %+v", action)
			}
		})
	}
}

func TestBelowMinimumRecoversWithinBudget(t *testing.T) {
	captureJournal(t)
	large := Shape{OCPUs: 4, MemoryGB: 24}
	for _, mode := range []string{"largest fits", "minimum fits", "minimum too expensive", "dry run"} {
		t.Run(mode, func(t *testing.T) {
			policy := testPolicy()
			policy.MonthlyBudget = policy.MonthlyCost(2, large) + policy.MonthlyCost(1, small) + 1
			wantShape := small
			switch mode {
			case "largest fits":
				policy.MonthlyBudget = policy.MonthlyCost(3, large) + 1
				wantShape = large
			case "minimum too expensive":
				policy.MonthlyBudget = policy.MonthlyCost(2, large)
			case "dry run":
				policy.DryRun = true
			}
			cell := newFakeCell(2, large, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			action, err := s.controller.Tick(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "minimum too expensive" {
				if action.Kind != KindHold || action.Reason != ReasonBudget || len(cell.callLog()) != 0 || cell.nodes() != 2 {
					t.Fatalf("unaffordable recovery acted: %+v calls=%v", action, cell.callLog())
				}
				return
			}
			if action.Kind != KindScaleOut || action.Reason != ReasonBelowMin || action.To != wantShape || action.MonthlyCost > policy.MonthlyBudget {
				t.Fatalf("affordable recovery held or chose wrong shape: %+v", action)
			}
			if mode == "dry run" {
				if cell.nodes() != 2 || len(cell.callLog()) != 0 {
					t.Fatal("dry run mutated the cell")
				}
			} else if cell.nodes() != policy.Nodes.Min || len(cell.callLog()) != 2 || cell.instances[2].Shape != wantShape || cell.state[action.Node] != StateReady {
				t.Fatalf("recovery did not launch and join: nodes=%d calls=%v", cell.nodes(), cell.callLog())
			}
			if mode == "minimum fits" {
				s.now = s.now.Add(time.Hour)
				// An unaffordable convergence-up must not strand the recovered
				// mixed cell; quiet peers can still converge down safely.
				action, err := s.controller.Tick(t.Context())
				if err != nil || action.Kind != KindHold || action.Reason != ReasonSustaining {
					t.Fatalf("mixed cell did not respect downsizing hysteresis: %+v err=%v", action, err)
				}
				s.now = s.now.Add(policy.sustainDown() + time.Second)
				action, err = s.controller.Tick(t.Context())
				if err != nil || action.Kind != KindResize || action.To != small || action.MonthlyCost > policy.MonthlyBudget || len(cell.callLog()) != 4 {
					t.Fatalf("recovered mixed cell got stranded: %+v err=%v calls=%v", action, err, cell.callLog())
				}
			}
		})
	}
}

func TestBelowMinimumReservesFullRecoveryBudget(t *testing.T) {
	for _, test := range []struct {
		name       string
		nodes      int
		shape      Shape
		budget     float64
		cpuDemand  float64
		firstKind  Kind
		firstShape Shape
	}{
		{"reserve remaining launches", 3, Shape{4, 24}, 8, 0.1, KindScaleOut, small},
		{"larger launches fit full recovery", 3, Shape{4, 24}, 10, 0.1, KindScaleOut, Shape{4, 24}},
		{"repair stranded cell", 4, Shape{4, 24}, 8, 0.1, KindResize, small},
		{"safe intermediate correction", 3, Shape{8, 48}, 10, 1.6, KindResize, Shape{4, 24}},
		{"unsafe correction holds", 4, Shape{4, 24}, 8, 2.4, KindHold, Shape{}},
		{"unsafe correction preserves full reserve", 3, Shape{4, 24}, 7, 1.8, KindHold, Shape{}},
		{"unsafe correction allows affordable recovery", 3, Shape{4, 24}, 8, 1.8, KindScaleOut, small},
	} {
		t.Run(test.name, func(t *testing.T) {
			captureJournal(t)
			policy := testPolicy()
			policy.Nodes.Min = 5
			policy.Prices = Prices{OCPUHour: 1.0 / (2 * hoursPerMonth)} // Minimum shape costs one unit.
			policy.MonthlyBudget = test.budget
			policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0
			policy.MaxActionsPerHour = 60
			cell := newFakeCell(test.nodes, test.shape, 1, 50)
			s := newSim(t, policy, cell, time.Minute)
			s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
				for _, instance := range cell.instances {
					if instance.Name == p.Node {
						p.CPUUtil = test.cpuDemand / instance.Shape.OCPUs
					}
				}
			}}
			first, err := s.controller.Tick(t.Context())
			if err != nil || first.Kind != test.firstKind || first.To != test.firstShape {
				t.Fatalf("minimum recovery chose wrong first action: %+v err=%v", first, err)
			}
			if test.firstKind == KindHold {
				if first.Reason != ReasonBudget || len(cell.callLog()) != 0 {
					t.Fatalf("unsafe downsize escaped rails: %+v calls=%v", first, cell.callLog())
				}
				return
			}
			for range 3 {
				if cell.nodes() == policy.Nodes.Min {
					break
				}
				s.now = s.now.Add(time.Minute)
				action, err := s.controller.Tick(t.Context())
				if err != nil || action.Kind != KindScaleOut || action.Reason != ReasonBelowMin || action.MonthlyCost > policy.MonthlyBudget {
					t.Fatalf("remaining minimum recovery was stranded: %+v err=%v calls=%v", action, err, cell.callLog())
				}
			}
			if cell.nodes() != policy.Nodes.Min {
				t.Fatalf("minimum recovery stopped at %d nodes", cell.nodes())
			}
			cost := 0.0
			for _, instance := range cell.instances {
				cost += policy.MonthlyCost(1, instance.Shape)
				if cell.state[instance.Name] != StateReady {
					t.Fatalf("recovery left %s unready", instance.Name)
				}
			}
			if cost > policy.MonthlyBudget {
				t.Fatalf("recovered minimum costs %g, budget %g", cost, policy.MonthlyBudget)
			}
		})
	}
}

func TestBelowMinimumCorrectionPreservesRails(t *testing.T) {
	for _, mode := range []string{"allowed", "missing inventory", "replica quorum", "cooldown", "dry run"} {
		t.Run(mode, func(t *testing.T) {
			captureJournal(t)
			policy := testPolicy()
			policy.Nodes.Min = 5
			policy.Prices = Prices{OCPUHour: 1.0 / (2 * hoursPerMonth)}
			policy.MonthlyBudget = 8
			cell := newFakeCell(4, Shape{4, 24}, 1, 50)
			s := newSim(t, policy, cell, time.Minute)
			state := s.observe()
			history := History{}
			wantKind, wantReason := KindHold, ReasonQuorum
			switch mode {
			case "allowed", "dry run":
				wantKind, wantReason = KindResize, ReasonBelowMin
				policy.DryRun = mode == "dry run"
				s.controller.config.Policy = policy
			case "missing inventory":
				state.Replicas = nil
			case "replica quorum":
				state.Replicas.Placements[0].LiveReplicas = []string{state.Nodes[0].Name}
			case "cooldown":
				history.LastAction = state.Now
				wantReason = ReasonCooldown
			}
			action, _ := Decide(policy, state, history)
			if action.Kind != wantKind || action.Reason != wantReason {
				t.Fatalf("corrective resize bypassed %s rail: %+v", mode, action)
			}
			if mode == "allowed" || mode == "dry run" {
				action, err := s.controller.Tick(t.Context())
				if err != nil || action.Kind != KindResize || (len(cell.callLog()) == 0) != policy.DryRun {
					t.Fatalf("corrective resize execution mode=%s: %+v err=%v calls=%v", mode, action, err, cell.callLog())
				}
			} else if len(cell.callLog()) != 0 {
				t.Fatal("refused correction mutated the cell")
			}
		})
	}
}

func TestCorrectiveResizeBudgetAfterEachEffect(t *testing.T) {
	for _, resource := range []string{"CPU", "memory"} {
		for _, order := range []string{"growth first", "shrink first"} {
			for _, interrupted := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/interrupted=%t", resource, order, interrupted), func(t *testing.T) {
					captureJournal(t)
					policy := testPolicy()
					policy.Nodes.Min = 5
					policy.Prices = Prices{OCPUHour: 1.0 / (2 * hoursPerMonth)}
					policy.MonthlyBudget = 10
					policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0
					low, high := small, Shape{8, 48}
					if resource == "memory" {
						policy.Prices = Prices{MemoryGBHour: 1.0 / (12 * hoursPerMonth)}
						low, high = Shape{4, 12}, Shape{4, 48}
					}
					cell := newFakeCell(4, low, 1, 50)
					large := 2
					if order == "shrink first" {
						large = 0
					}
					cell.instances[large].Shape, cell.instances[large+1].Shape = high, high
					var costs []float64
					cell.onResize = func(string) {
						cost := 0.0
						for _, instance := range cell.instances {
							cost += policy.MonthlyCost(1, instance.Shape)
						}
						costs = append(costs, cost)
						if interrupted {
							// Stop convergence after the accepted first effect.
							cell.unread[cell.instances[(large+2)%4].Name] = true
						}
					}
					s := newSim(t, policy, cell, time.Minute)
					action, err := s.controller.Tick(t.Context())
					if action.Kind != KindResize || action.To != (Shape{4, 24}) || (err != nil) != interrupted {
						t.Fatalf("correction did not run: %+v err=%v calls=%v", action, err, cell.callLog())
					}
					wantEffects := 4
					if interrupted {
						wantEffects = 1
					}
					if len(costs) != wantEffects || len(cell.callLog()) != wantEffects {
						t.Fatalf("correction did not preserve convergence gates: costs=%v calls=%v", costs, cell.callLog())
					}
					for _, cost := range costs {
						if cost > policy.MonthlyBudget {
							t.Fatalf("resize exceeded budget before completion: costs=%v budget=%g calls=%v", costs, policy.MonthlyBudget, cell.callLog())
						}
					}
				})
			}
		}
	}
}

func TestCorrectiveResizeRejectsChangedCapacityPlan(t *testing.T) {
	for _, phase := range []string{"stable", "before first resize", "after one resize"} {
		t.Run(phase, func(t *testing.T) {
			captureJournal(t)
			policy := testPolicy()
			policy.Nodes.Min = 5
			policy.Prices = Prices{OCPUHour: 1.0 / (2 * hoursPerMonth)}
			policy.MonthlyBudget = 10
			policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0
			cell := newFakeCell(4, small, 1, 50)
			cell.instances[2].Shape, cell.instances[3].Shape = Shape{8, 48}, Shape{8, 48}
			s := newSim(t, policy, cell, time.Minute)
			original := s.observe()
			injected := false
			s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
				_, _, restarting := s.controller.restartFor("gru-1-db-3")
				if injected || phase == "stable" || phase == "after one resize" && (len(cell.callLog()) != 1 || restarting) {
					return
				}
				cell.instances[0].Shape, cell.instances[3].Shape = Shape{8, 48}, small
				if phase == "before first resize" {
					cell.instances[1].Shape, cell.instances[2].Shape = Shape{8, 48}, small
				}
				cell.delayedSample[cell.instances[0].Name] = true // Newly measured after discovery + skew.
				injected = true
			}}
			err := s.controller.rollingResize(t.Context(), original, Shape{4, 24})
			wantEffects := 0
			if phase == "stable" {
				wantEffects = 4
				if err != nil {
					t.Fatalf("controlled resize failed to update its own expected shape: %v", err)
				}
			} else {
				if phase == "after one resize" {
					wantEffects = 1
				}
				if !injected || err == nil || !strings.Contains(err.Error(), "action plan") {
					t.Fatalf("fresh capacity change did not invalidate the original plan: err=%v injected=%t calls=%v", err, injected, cell.callLog())
				}
				for _, node := range original.Nodes {
					if node.Name == "gru-1-db-3" && phase == "after one resize" {
						continue // The one controlled restart explicitly binds a successor.
					}
					p, found := s.controller.lastPressure[node.Identity()]
					if !found || !p.Fresh(s.now) || !p.SampledAt.After(s.controller.pressureAfter[node.Name]) || p.State != StateReady {
						t.Fatalf("refusal used missing/stale identity evidence instead of the plan mismatch: %s found=%t sample=%s", node.Name, found, p.SampledAt)
					}
				}
			}
			if len(cell.callLog()) != wantEffects {
				t.Fatalf("capacity change escaped before a later effect: %v", cell.callLog())
			}
		})
	}
}

func TestCorrectiveResizeChecksCapacityAfterFinalInventory(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed=%t", changed), func(t *testing.T) {
			audit := captureJournal(t)
			policy := testPolicy()
			policy.Nodes.Min = 5
			policy.Prices = Prices{OCPUHour: 1.0 / (2 * hoursPerMonth)}
			policy.MonthlyBudget = 10
			policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0
			cell := newFakeCell(4, small, 1, 50)
			cell.instances[2].Shape, cell.instances[3].Shape = Shape{8, 48}, Shape{8, 48}
			s := newSim(t, policy, cell, time.Minute)
			reads, injected := 0, false
			s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
				_, _, pending := s.controller.restartFor("gru-1-db-2")
				if len(cell.callLog()) != 4 || pending {
					return
				}
				reads++
				// Three post-restart recheck reads and two wait entry reads
				// precede the final inventory observation's first OCI read.
				if changed && reads == 6 {
					cell.instances[0].Shape = Shape{8, 48}
					cell.delayedSample[cell.instances[0].Name] = true
					injected = true
				}
			}}
			action, err := s.controller.Tick(t.Context())
			if action.Kind != KindResize || action.To != (Shape{4, 24}) || injected != changed || len(cell.callLog()) != 4 {
				t.Fatalf("final inventory boundary not reached: action=%+v err=%v injected=%t reads=%d calls=%v", action, err, injected, reads, cell.callLog())
			}
			status := decisionlog.StatusSucceeded
			if changed {
				status = decisionlog.StatusFailed
				id := s.controller.activeIdentities[cell.instances[0].Name]
				p, found := s.controller.lastPressure[id]
				if !found || !p.Fresh(s.now) || !p.SampledAt.After(s.controller.pressureAfter[id.Name]) || p.State != StateReady ||
					s.controller.lastReplicas == nil || !s.controller.lastReplicas.SampledAt.After(s.controller.replicasAfter) {
					t.Fatal("capacity mismatch was not isolated from readiness and inventory freshness")
				}
				if err == nil || !strings.Contains(err.Error(), "action plan") || s.controller.History().Failures != 1 {
					t.Fatalf("changed capacity incorrectly completed the resize: err=%v history=%+v", err, s.controller.History())
				}
			} else if err != nil {
				t.Fatalf("stable completed plan was refused: %v", err)
			}
			if len(audit.decisions) != 2 || audit.decisions[1].Status != status {
				t.Fatalf("resize completion audit ignored its capacity plan: %+v", audit.decisions)
			}
		})
	}
}

func TestScaleOutChecksCapacityAfterJoin(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, capacity := range []Shape{small, {8, 48}, {2, 48}} {
			t.Run(fmt.Sprintf("recovery=%t/capacity=%s", recovery, capacity), func(t *testing.T) {
				audit := captureJournal(t)
				policy := testPolicy()
				policy.Nodes.Min = 5
				policy.Prices = Prices{OCPUHour: 1.0 / (2 * hoursPerMonth)}
				policy.MonthlyBudget = 8
				policy.CooldownSeconds, policy.ScaleDownCooldownSeconds = 0, 0
				cell := newFakeCell(3, Shape{4, 24}, 1, 50)
				effects := 2
				if recovery {
					if _, err := cell.Launch(t.Context(), "gru-1-db-4", small); err != nil {
						t.Fatal(err)
					}
					cell.calls = nil
					effects = 1
				}
				s := newSim(t, policy, cell, time.Minute)
				changed, injected := capacity != small, false
				s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
					if changed && !injected && len(cell.callLog()) == effects && cell.state["gru-1-db-4"] == StateReady {
						cell.instances[3].Shape = capacity
						cell.delayedSample["gru-1-db-4"] = true
						injected = true
					}
				}}
				action, err := s.controller.Tick(t.Context())
				if action.Kind != KindScaleOut || action.To != small || action.Recovery != recovery || len(cell.callLog()) != effects || injected != changed {
					t.Fatalf("post-join boundary not reached: action=%+v err=%v injected=%t calls=%v", action, err, injected, cell.callLog())
				}
				status := decisionlog.StatusSucceeded
				if changed {
					status = decisionlog.StatusFailed
					id := s.controller.activeIdentities["gru-1-db-4"]
					p, found := s.controller.lastPressure[id]
					if !found || p.State != StateReady || !p.Fresh(s.now) || !p.SampledAt.After(s.controller.pressureAfter[id.Name]) {
						t.Fatal("post-join probe did not supply fresh readiness for the unchanged identity")
					}
					if err == nil || !strings.Contains(err.Error(), "action plan") {
						t.Fatalf("post-join capacity change falsely completed: err=%v", err)
					}
				} else if err != nil {
					t.Fatalf("stable join completion failed: %v", err)
				}
				if len(audit.decisions) != 2 || audit.decisions[1].Status != status {
					t.Fatalf("join completion audit ignored capacity: %+v", audit.decisions)
				}
			})
		}
	}
}

func TestActionCapacityPlanRejectsFreshShapeChanges(t *testing.T) {
	for _, action := range []Action{
		{Kind: KindScaleOut, Node: "gru-1-db-5", To: small},
		{Kind: KindScaleIn, Node: "gru-1-db-4", Reason: ReasonLowPressure},
		{Kind: KindResize, To: Shape{4, 24}},
		{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: project("org-1-0")},
	} {
		t.Run(string(action.Kind), func(t *testing.T) {
			cell := newFakeCell(4, small, 4, 100)
			s := newSim(t, testPolicy(), cell, time.Minute)
			if action.Kind == KindRebalance {
				s.controller.config.Source = changedLoad{fakeCell: cell, change: func(p *NodePressure) {
					if p.Node == action.Node {
						p.CPUUtil = 0.9
					}
				}}
			}
			original := s.observe()
			injected := false
			s.controller.config.Cloud = &actionIdentityCloud{fakeCell: cell, beforeList: func() {
				if !injected {
					cell.instances[1].Shape = Shape{4, 24}
					cell.delayedSample[cell.instances[0].Name] = true
					injected = true
				}
			}}
			err := s.controller.apply(t.Context(), original, action)
			p, found := s.controller.lastPressure[original.Nodes[1].Identity()]
			if !injected || !found || !p.Fresh(s.now) || !p.SampledAt.After(s.controller.pressureAfter[p.Node]) || p.State != StateReady {
				t.Fatal("capacity-plan probe did not supply fresh evidence for the unchanged identity")
			}
			if err == nil || !strings.Contains(err.Error(), "action plan") || len(cell.callLog()) != 0 {
				t.Fatalf("fresh shape change preserved an obsolete action plan: err=%v calls=%v", err, cell.callLog())
			}
		})
	}
}

func TestMixedShapeHotspotFitsNewNode(t *testing.T) {
	large := Shape{OCPUs: 4, MemoryGB: 24}
	for _, mode := range []string{"fits", "budget cap", "node cap", "request cap"} {
		t.Run(mode, func(t *testing.T) {
			policy := testPolicy()
			policy.Shape.MaxOCPUs = large.OCPUs
			// Three small nodes and one large node can afford one new large
			// node, but cannot afford converging all four to the large shape.
			current := policy.MonthlyCost(3, small) + policy.MonthlyCost(1, large)
			policy.MonthlyBudget = current + policy.MonthlyCost(1, large) + 1
			state := observeState(t, policy, newFakeCell(4, small, 2, 100))
			state.Nodes[3].Shape = large
			for _, node := range state.Nodes {
				node.Pressure.CPUUtil = 0.4
			}
			hot := state.Nodes[0].Pressure
			hot.CPUUtil = 0.9
			hot.TopTenants = []TenantLoad{{Project: project("noisy"), RequestRate: 100, CPUShare: 0.8}}
			want, reason := KindScaleOut, ReasonHotspot
			switch mode {
			case "budget cap":
				policy.MonthlyBudget = current + policy.MonthlyCost(1, large) - 1
				want, reason = KindHold, ReasonBudget
			case "node cap":
				policy.Nodes.Max = len(state.Nodes)
				want, reason = KindHold, ReasonAtCapacity
			case "request cap":
				hot.TopTenants[0].RequestRate = policy.Targets.RequestRate
				hot.RequestRate = policy.Targets.RequestRate
				want, reason = KindHold, ReasonAtCapacity
			}
			// The tenant uses 0.72 CPU on its 2-OCPU source, but only 0.36
			// on the proposed 4-OCPU node. Existing peers exceed 0.7 with it.
			action := act(policy, state, History{})
			if action.Kind != want || action.Reason != reason {
				t.Fatalf("mixed-shape hotspot = %+v, want %s/%s", action, want, reason)
			}
			if action.Kind == KindScaleOut && (action.To != large || action.Node != "gru-1-db-5" || action.MonthlyCost > policy.MonthlyBudget) {
				t.Fatalf("scale-out shape or budget is wrong: %+v", action)
			}
		})
	}
}

func TestPolicyRejectsIndistinguishableResizeStep(t *testing.T) {
	for _, step := range []float64{0.0001, 0.0005, 0.002} {
		policy := testPolicy()
		policy.Shape.StepOCPUs = step
		err := policy.Validate()
		if step == 0.0001 {
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("indistinguishable step passed validation: %v", err)
			}
			if _, err := New(Config{Cell: "gru-1", Policy: policy}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("invalid step reached controller setup: %v", err)
			}
		} else if err != nil {
			t.Fatalf("distinguishable step %g rejected: %v", step, err)
		}
	}
}

func TestClippedResizeNeverRecordsSuccessWithoutCapacity(t *testing.T) {
	captureJournal(t)
	for _, mode := range []string{"hot grows horizontally", "hot at max", "hotspot at max", "quiet at min"} {
		t.Run(mode, func(t *testing.T) {
			policy := testPolicy()
			policy.SustainUpSeconds, policy.SustainDownSeconds = 0, 0
			policy.Shape.MaxOCPUs = 2.0001 // Final clipped increment is below both shape tolerances.
			policy.Nodes.Max = 3
			shape, want := small, KindHold
			rate := 500.0
			switch mode {
			case "hot grows horizontally":
				policy.Nodes.Max, want = 4, KindScaleOut
			case "quiet at min":
				shape, rate = policy.Shape.at(policy.Shape.MaxOCPUs), 20
			}
			cell := newFakeCell(3, shape, 2, rate)
			cell.coresPerRequest = 0.002
			if mode == "hotspot at max" {
				cell.tenants["gru-1-db-2"], cell.tenants["gru-1-db-3"] = nil, nil
				cell.tenants["gru-1-db-1"] = []TenantLoad{{Project: project("huge"), RequestRate: 1000}}
			}
			s := newSim(t, policy, cell, time.Minute)
			action, err := s.controller.Tick(t.Context())
			if err != nil || action.Kind != want {
				t.Fatalf("clipped step chose a no-op resize: %+v err=%v", action, err)
			}
			if want == KindHold && (len(cell.callLog()) != 0 || len(s.controller.History().Actions) != 0) {
				t.Fatalf("no-op consumed an action: %+v calls=%v", s.controller.History(), cell.callLog())
			}
		})
	}
}
