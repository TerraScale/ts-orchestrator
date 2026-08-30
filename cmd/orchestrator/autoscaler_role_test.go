package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/autoscaling"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

func testAutoscalerHeartbeat(t *testing.T, node string, unixSeconds int64) []byte {
	t.Helper()
	nodeID, err := hostagent.NewNodeId(node)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := hostagent.NewNodeMetricsSample(1<<30, 0, 100, 0, 128, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat, err := hostagent.NewNodeHeartbeat(nodeID, unixSeconds, metrics)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestAutoscalerRoleBindsHeartbeatsToSubjectAndRejectsReplay(t *testing.T) {
	role := &autoscalerRole{
		settings: autoscalerRoleSettings{TickInterval: time.Second},
		nodes:    make(map[string]*autoscalerNodeEntry),
	}
	now := time.Now().Unix()
	validSubject := "terrascale.node.v1.node-a.heartbeat"
	role.handleHeartbeat(&nats.Msg{Subject: validSubject, Data: testAutoscalerHeartbeat(t, "node-b", now)})
	if len(role.nodes) != 0 {
		t.Fatal("a heartbeat claiming a different node must be rejected")
	}
	role.handleHeartbeat(&nats.Msg{Subject: validSubject, Data: testAutoscalerHeartbeat(t, "node-a", now)})
	entry, present := role.nodes["node-a"]
	if !present || entry.lastHeartbeatUnixSec != now {
		t.Fatalf("bound heartbeat was not recorded: %+v", role.nodes)
	}
	role.handleHeartbeat(&nats.Msg{Subject: validSubject, Data: testAutoscalerHeartbeat(t, "node-a", now-1)})
	if role.nodes["node-a"].lastHeartbeatUnixSec != now {
		t.Fatal("an older heartbeat must not replace the latest sample")
	}
	role.handleHeartbeat(&nats.Msg{Subject: "terrascale.node.v1.node-a.other", Data: testAutoscalerHeartbeat(t, "node-a", now+1)})
	if role.nodes["node-a"].lastHeartbeatUnixSec != now {
		t.Fatal("a non-heartbeat subject must be rejected")
	}
}

func TestAutoscalerRoleDefersDrainWithoutReplicaPlacementState(t *testing.T) {
	policy, err := stateful.NewDrainPolicy(1)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := stateful.NewReplicaDrainSafetyEvaluator(policy)
	if err != nil {
		t.Fatal(err)
	}
	role := &autoscalerRole{replicaDrains: evaluator}
	decision, err := role.EvaluateDrainSafety(context.Background(), statefulCandidateForRoleTest(t))
	if err != nil {
		t.Fatalf("drain decision: %v", err)
	}
	if decision.Allowed || !strings.Contains(decision.Reason, "unavailable") {
		t.Fatalf("drain must defer without placement state: %+v", decision)
	}
}

func statefulCandidateForRoleTest(t *testing.T) stateful.NodeDrainCandidate {
	t.Helper()
	candidate, err := stateful.NewNodeDrainCandidate("node-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

var _ autoscaling.DrainSafetyEvaluator = (*autoscalerRole)(nil)
