package cellscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

func safeReplicaSnapshot(now time.Time, cells ...*fakeCell) ReplicaSnapshot {
	members := []NodeIdentity{}
	if len(cells) > 0 {
		members = cells[0].memberIdentities()
	} else {
		for n := 1; n <= 4; n++ {
			name := NodeName("gru-1", n)
			members = append(members, NodeIdentity{Name: name, InstanceID: "ocid-" + name, Incarnation: entityid.Derive("test-process", name+"-p1")})
		}
	}
	return ReplicaSnapshot{Schema: 1, Cell: "gru-1", SampledAt: now, Complete: true, Members: members,
		Placements: []ReplicaPlacement{
			{Org: entityid.Derive("test-entity", "acme"), Database: entityid.Derive("test-entity", "primary"), Shard: 1, LiveReplicas: []string{"gru-1-db-1", "gru-1-db-2", "gru-1-db-3"}},
			{Org: entityid.Derive("test-entity", "other"), Database: entityid.Derive("test-entity", "quiet"), Shard: 2, LiveReplicas: []string{"gru-1-db-1", "gru-1-db-2", "gru-1-db-3"}},
		}}
}

func TestReplicaInventoryRequiresExactIdentityMembership(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		change func(*ReplicaSnapshot)
	}{
		{"old instance", func(s *ReplicaSnapshot) { s.Members[0].InstanceID = "predecessor-ocid" }},
		{"old incarnation", func(s *ReplicaSnapshot) { s.Members[0].Incarnation = "0000000000RHB5KCASP9GW9MZF" }},
		{"missing empty member", func(s *ReplicaSnapshot) { s.Members = s.Members[:3] }},
		{"duplicate member", func(s *ReplicaSnapshot) { s.Members[1] = s.Members[0] }},
		{"unknown member", func(s *ReplicaSnapshot) { s.Members[3] = fakeNodeIdentity("gru-1-db-5") }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			cell := newFakeCell(4, small, 0, 0)
			state := observeState(t, testPolicy(), cell)
			snapshot := safeReplicaSnapshot(state.Now, cell)
			snapshot.Placements = []ReplicaPlacement{}
			mutate.change(&snapshot)
			state.Replicas = &snapshot
			if err := validReplicaInventory(state); err == nil {
				t.Fatal("empty inventory authorized a different membership identity")
			}
		})
	}
}

func TestTerminationRequiresEveryPlacementToRetainReplicas(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*State)
		want   Kind
	}{
		{"safe", func(*State) {}, KindScaleIn},
		{"missing inventory", func(s *State) { s.Replicas = nil }, KindHold},
		{"partial inventory", func(s *State) { s.Replicas.Complete = false }, KindHold},
		{"missing placement list", func(s *State) { s.Replicas.Placements = nil }, KindHold},
		{"stale inventory", func(s *State) { s.Replicas.SampledAt = s.Now.Add(-MaxPressureAge - time.Second) }, KindHold},
		{"another cell", func(s *State) { s.Replicas.Cell = "gru-2" }, KindHold},
		{"quiet database loses copy", func(s *State) {
			s.Replicas.Placements[1].LiveReplicas = []string{"gru-1-db-1", "gru-1-db-2", "gru-1-db-4"}
		}, KindHold},
		{"quorum alone is insufficient", func(s *State) {
			s.Replicas.Placements[1].LiveReplicas = []string{"gru-1-db-1", "gru-1-db-2"}
		}, KindHold},
		{"duplicate replica", func(s *State) {
			s.Replicas.Placements[1].LiveReplicas[2] = "gru-1-db-2"
		}, KindHold},
		{"unknown node", func(s *State) {
			s.Replicas.Placements[1].LiveReplicas[2] = "gru-1-db-5"
		}, KindHold},
		{"unready replica", func(s *State) { s.Nodes[1].Pressure.State = StateJoining }, KindHold},
		{"lagging replica", func(s *State) { s.Nodes[1].Pressure.Load.ReplicationLagSeq = 5000 }, KindHold},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			state := observeState(t, policy, newFakeCell(4, small, 2, 150))
			snapshot := safeReplicaSnapshot(state.Now)
			state.Replicas = &snapshot
			test.change(&state)
			err := removalSafe(policy, state, "gru-1-db-4")
			if (err == nil) != (test.want == KindScaleIn) {
				t.Fatalf("termination gate = %v, want %s", err, test.want)
			}
			state.Nodes[3].Pressure.State = StateDrained
			action, _ := rails(policy, state, History{}, Action{Kind: KindScaleIn, Node: "gru-1-db-4", Recovery: true}, 0)
			if action.Kind != test.want || action.Kind == KindHold && action.Reason != ReasonQuorum {
				t.Fatalf("termination recovery rail = %+v, want %s", action, test.want)
			}
		})
	}
	for _, factor := range []int{1, 2} {
		policy := testPolicy()
		policy.ReplicationFactor = factor
		state := observeState(t, policy, newFakeCell(4, small, 2, 150))
		snapshot := safeReplicaSnapshot(state.Now)
		snapshot.Placements[1].LiveReplicas = []string{"gru-1-db-4"}
		if factor == 2 {
			snapshot.Placements[1].LiveReplicas = append(snapshot.Placements[1].LiveReplicas, "gru-1-db-1")
		}
		state.Replicas = &snapshot
		state.Nodes[3].Pressure.State = StateDrained
		if action := act(policy, state, History{}); action.Kind != KindHold || action.Reason != ReasonQuorum {
			t.Fatalf("factor %d with spare nodes lost a placement: %+v", factor, action)
		}
	}
}

func TestScaleInRechecksPlacementBeforeEachEffect(t *testing.T) {
	for _, afterDrain := range []bool{false, true} {
		t.Run(map[bool]string{false: "before drain", true: "before terminate"}[afterDrain], func(t *testing.T) {
			policy := testPolicy()
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, policy, cell, time.Minute)
			state := observeState(t, policy, cell)
			action := act(policy, state, History{})
			if action.Kind != KindScaleIn {
				t.Fatalf("setup did not scale in: %+v", action)
			}
			lost := !afterDrain
			cell.replicas = func() (ReplicaSnapshot, error) {
				if !s.now.After(s.controller.replicasAfter) {
					s.now = s.controller.replicasAfter.Add(time.Second)
				}
				snapshot := safeReplicaSnapshot(s.now)
				if lost {
					if afterDrain {
						snapshot.Placements[1].LiveReplicas = snapshot.Placements[1].LiveReplicas[:2]
					} else {
						snapshot.Placements[1].LiveReplicas[2] = "gru-1-db-5"
					}
				}
				return snapshot, nil
			}
			cell.after = map[string]func(string){"drain": func(string) { lost = true }}
			err := s.controller.apply(t.Context(), state, action)
			wantError := "replica inventory unavailable"
			if afterDrain {
				wantError = "context deadline exceeded"
			}
			if err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("unsafe placement removal: %v", err)
			}
			var want []string
			if afterDrain {
				want = []string{"drain gru-1-db-4"}
			}
			if !slices.Equal(cell.callLog(), want) {
				t.Fatalf("unsafe cloud effects: %v, want %v", cell.callLog(), want)
			}
			// Recovery cannot terminate an already drained node without proof.
			cell.state["gru-1-db-4"] = StateDrained
			if got, _ := Decide(policy, observeState(t, policy, cell), History{}); got.Kind != KindHold || got.Reason != ReasonQuorum {
				t.Fatalf("recovery bypassed placement quorum: %+v", got)
			}
		})
	}
}

func TestHTTPReplicaInventoryRequiresCompleteEvidence(t *testing.T) {
	want := safeReplicaSnapshot(time.Now().UTC())
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != ReplicaPath {
			t.Errorf("unexpected inventory request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	members := HTTPMembers{Client: server.Client(), Endpoint: EndpointTemplate(server.URL)}
	if got, err := members.Replicas(t.Context(), "gru-1-db-1"); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Replicas = %+v, %v", got, err)
	}
	complete := slices.Clone(body)
	for _, field := range []string{"schema", "cell", "sampled_at", "complete", "members", "placements", "org", "database", "shard", "live_replicas", "member.node", "member.instance_id", "member.incarnation"} {
		for _, missing := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "/null", true: "/missing"}[missing], func(t *testing.T) {
				var report map[string]any
				if err := json.Unmarshal(complete, &report); err != nil {
					t.Fatal(err)
				}
				object := report
				key := field
				if slices.Contains([]string{"org", "database", "shard", "live_replicas"}, field) {
					object = report["placements"].([]any)[0].(map[string]any)
				} else if memberField, ok := strings.CutPrefix(field, "member."); ok {
					object, key = report["members"].([]any)[0].(map[string]any), memberField
				}
				if missing {
					delete(object, key)
				} else {
					object[key] = nil
				}
				body, err = json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := members.Replicas(t.Context(), "gru-1-db-1"); err == nil {
					t.Fatal("incomplete inventory accepted")
				}
			})
		}
	}
	body = []byte(`{"schema":1,"schema":1}`)
	if _, err := members.Replicas(t.Context(), "gru-1-db-1"); err == nil {
		t.Fatal("duplicate inventory fields accepted")
	}
	body = []byte(strings.Repeat(" ", maxReplicaBytes+1))
	if _, err := members.Replicas(t.Context(), "gru-1-db-1"); err == nil {
		t.Fatal("oversized inventory accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := members.Replicas(ctx, "gru-1-db-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("inventory request ignored cancellation: %v", err)
	}
}
