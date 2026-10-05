package cellscale

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

type failedMembership struct {
	*fakeCell
	failJoin, failTerminate bool
	controller              *Controller
}

func (f *failedMembership) Replicas(ctx context.Context, node string) (ReplicaSnapshot, error) {
	return (liveReplicaInventory{f.fakeCell, f.controller}).Replicas(ctx, node)
}

func (f *failedMembership) Join(ctx context.Context, node NodeIdentity) error {
	if f.failJoin {
		return errors.New("temporary join failure")
	}
	return f.fakeCell.Join(ctx, node)
}

func (f *failedMembership) Terminate(ctx context.Context, id string) error {
	if f.failTerminate {
		return errors.New("temporary terminate failure")
	}
	return f.fakeCell.Terminate(ctx, id)
}

func TestMembershipRecoveryAfterFailure(t *testing.T) {
	for _, kind := range []Kind{KindScaleOut, KindScaleIn} {
		for _, restart := range []bool{false, true} {
			name := string(kind) + "/resume"
			if restart {
				name = string(kind) + "/restart"
			}
			t.Run(name, func(t *testing.T) {
				journal := captureJournal(t)
				policy := testPolicy()
				policy.MaxFailures = 1
				nodes, scale := 3, 2.6
				if kind == KindScaleIn {
					nodes, scale = 4, 1
				}
				cell := newFakeCell(nodes, small, 2, 150)
				if kind == KindScaleOut {
					cell = newFakeCell(nodes, small, 4, 250)
				}
				cell.setScale(scale)
				fault := &failedMembership{fakeCell: cell, failJoin: kind == KindScaleOut, failTerminate: kind == KindScaleIn}
				s := newSim(t, policy, cell, time.Minute)
				fault.controller = s.controller
				s.controller.config.Cloud, s.controller.config.Members = fault, fault
				wantError := "temporary join failure"
				if kind == KindScaleIn {
					wantError = "temporary terminate failure"
				}
				if err := runUntilError(t, s, 60); err == nil || !strings.Contains(err.Error(), wantError) || !s.controller.History().Paused {
					t.Fatalf("failed action did not pause: %v, %+v", err, s.controller.History())
				}
				fault.failJoin, fault.failTerminate = false, false
				if restart {
					var err error
					s.controller, err = New(s.controller.config)
					if err != nil {
						t.Fatal(err)
					}
					fault.controller = s.controller
				} else {
					s.controller.Resume()
				}
				s.now = s.now.Add(31 * time.Minute)
				action, err := s.controller.Tick(t.Context())
				if err != nil || action.Kind != kind || !action.Recovery {
					t.Fatalf("recovery = %+v, %v", action, err)
				}
				want := []string{"launch gru-1-db-4 2 OCPU/12 GB", "join gru-1-db-4"}
				if kind == KindScaleIn {
					want = []string{"drain gru-1-db-4", "terminate gru-1-db-4"}
				}
				if got := cell.callLog(); !slices.Equal(got, want) {
					t.Fatalf("duplicated membership steps: %v, want %v", got, want)
				}
				if !slices.ContainsFunc(journal.decisions, func(d decisionlog.Decision) bool {
					return d.Status == decisionlog.StatusSucceeded && d.Attrs["recovery"] == "true"
				}) {
					t.Fatal("recovery was not audited")
				}
			})
		}
	}
}

func TestMembershipRecoveryRails(t *testing.T) {
	for _, state := range []NodeState{StateJoining, StateDraining, StateDrained} {
		t.Run(string(state), func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(4, small, 2, 150)
			cell.state["gru-1-db-4"] = state
			observed := observeState(t, policy, cell)
			action, _ := Decide(policy, observed, History{})
			if action.Kind == KindHold || !action.Recovery {
				t.Fatalf("unfinished membership held: %+v", action)
			}
			if state == StateJoining && action.MonthlyCost != policy.MonthlyCost(4, small) {
				t.Fatalf("recovery double counted the existing node: %+v", action)
			}
			for reason, change := range map[string]func(*State, *History){
				ReasonPaused:   func(_ *State, h *History) { h.Paused = true },
				ReasonRollout:  func(s *State, _ *History) { s.RolloutInFlight = true },
				ReasonCooldown: func(s *State, h *History) { h.LastAction = s.Now },
				ReasonRateLimit: func(s *State, h *History) {
					h.Actions = make([]time.Time, policy.MaxActionsPerHour)
					for i := range h.Actions {
						h.Actions[i] = s.Now
					}
				},
			} {
				s, history := observed, History{}
				change(&s, &history)
				if got, _ := Decide(policy, s, history); got.Kind != KindHold || got.Reason != reason {
					t.Fatalf("%s recovery bypassed %s: %+v", state, reason, got)
				}
			}
			cell.unread["gru-1-db-2"] = true
			if got, _ := Decide(policy, observeState(t, policy, cell), History{}); got.Reason != ReasonNotSettled {
				t.Fatalf("recovery with unreadable peer: %+v", got)
			}
			cell.unread["gru-1-db-2"] = false
			cell.lag = map[string]uint64{"gru-1-db-2": 5000}
			if got, _ := Decide(policy, observeState(t, policy, cell), History{}); got.Reason != ReasonLag {
				t.Fatalf("recovery with lagging peer: %+v", got)
			}
			cell.lag = nil
			cell.release["gru-1-db-4"] = "r2"
			if got, _ := Decide(policy, observeState(t, policy, cell), History{}); got.Reason != ReasonRollout {
				t.Fatalf("recovery with release skew: %+v", got)
			}
			cell.release["gru-1-db-4"] = "r1"
			if state != StateJoining {
				cell.instances = cell.instances[1:]
				if got, _ := Decide(policy, observeState(t, policy, cell), History{}); got.Reason != ReasonQuorum {
					t.Fatalf("drain recovery removed a quorum member: %+v", got)
				}
			}
		})
	}
}

func TestScaleOutRejectsJoiningReleaseSkew(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	cell.after = map[string]func(string){"launch": func(node string) { cell.release[node] = "r2" }}
	cell.setScale(2.6)
	err := runUntilError(t, newSim(t, testPolicy(), cell, time.Minute), 30)
	if err == nil || !strings.Contains(err.Error(), "rollout is in flight") {
		t.Fatalf("joined another release: %v", err)
	}
	if got := cell.callLog(); !slices.Equal(got, []string{"launch gru-1-db-4 2 OCPU/12 GB"}) {
		t.Fatalf("joined mixed-release node: %v", got)
	}
}

func TestMembershipRecoveryDryRun(t *testing.T) {
	journal := captureJournal(t)
	policy := testPolicy()
	policy.DryRun = true
	cell := newFakeCell(4, small, 2, 150)
	cell.state["gru-1-db-4"] = StateDrained
	s := newSim(t, policy, cell, time.Minute)
	s.now = s.now.Add(31 * time.Minute)
	action, err := s.controller.Tick(t.Context())
	if err != nil || action.Kind != KindScaleIn || !action.Recovery || len(cell.callLog()) != 0 || cell.nodes() != 4 {
		t.Fatalf("dry recovery = %+v, %v, calls %v", action, err, cell.callLog())
	}
	if !slices.ContainsFunc(journal.decisions, func(d decisionlog.Decision) bool {
		return d.Status == decisionlog.StatusPending && d.Attrs["recovery"] == "true" && d.Attrs["dry_run"] == "true"
	}) {
		t.Fatal("dry recovery was not audited")
	}
}

type deadlineCloud struct {
	*fakeCell
	block bool
}

func (c *deadlineCloud) List(ctx context.Context) ([]Instance, error) {
	if c.block {
		<-ctx.Done()
	}
	return c.fakeCell.List(ctx)
}

func (c *deadlineCloud) Terminate(ctx context.Context, id string) error {
	err := c.fakeCell.Terminate(ctx, id)
	c.block = true
	return err
}

func (c *deadlineCloud) Resize(ctx context.Context, id string, shape Shape) error {
	err := c.fakeCell.Resize(ctx, id, shape)
	c.block = true
	return err
}

type deadlineSource struct{ *fakeCell }

func (s deadlineSource) Pressure(ctx context.Context, node string) (NodePressure, error) {
	<-ctx.Done()
	return s.fakeCell.Pressure(ctx, node)
}

func TestWaitDeadlineReachesRequests(t *testing.T) {
	for _, operation := range []string{"pressure", "termination", "resize"} {
		t.Run(operation, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			state, err := s.controller.observe(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			s.controller.config.ReadyTimeout = 20 * time.Millisecond
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			start := time.Now()
			if operation == "pressure" {
				s.controller.config.Source = deadlineSource{cell}
				err = s.controller.waitNode(ctx, identities(state.Nodes), "gru-1-db-4", func(p NodePressure) bool { return p.State == StateReady })
			} else {
				s.controller.config.Cloud = &deadlineCloud{fakeCell: cell}
				action := Action{Kind: KindScaleIn, Node: "gru-1-db-4"}
				if operation == "resize" {
					action = Action{Kind: KindResize, From: small, To: Shape{OCPUs: 4, MemoryGB: 24}}
				}
				err = s.controller.apply(ctx, state, action)
			}
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("%s exceeded wait deadline or accepted late success: %v, elapsed %s", operation, err, time.Since(start))
			}
		})
	}
}
