package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/autoscaling"
	"terrascale.tech/orchestrator/src/orchestrator/control"
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

func TestAutoscalerRoleConfigurationRequiresAuthenticatedTLSNATS(t *testing.T) {
	values := map[string]string{"TS_ORCH_NATS_URL": "tls://127.0.0.1:4222"}
	if _, err := autoscalerRoleConfiguration(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}); err == nil || !strings.Contains(err.Error(), "TS_ORCH_NATS_NKEY_FILE") {
		t.Fatalf("autoscaler accepted missing NKey credentials: %v", err)
	}
}

func TestAutoscalerProviderIsExplicitlyLocalDevOnly(t *testing.T) {
	for _, value := range []string{"", "oci", "local"} {
		lookup := func(name string) (string, bool) {
			if name != autoscalerProviderEnvironment || value == "" {
				return "", false
			}
			return value, true
		}
		if err := autoscalerRequireLocalDevProvider(lookup); err == nil {
			t.Fatalf("provider %q was accepted", value)
		}
	}
	if err := autoscalerRequireLocalDevProvider(func(name string) (string, bool) {
		return "local-dev", name == autoscalerProviderEnvironment
	}); err != nil {
		t.Fatalf("local-dev provider: %v", err)
	}
}

func TestAutoscalerNodeAgentArgumentsUseTheDistinctNodeIdentity(t *testing.T) {
	settings := autoscalerRoleSettings{
		NatsNKeyFile:     "/run/autoscaler/control.seed",
		NatsTls:          &control.NatsTlsFiles{CaFile: "/run/autoscaler/ca.pem", CertificateFile: "/run/autoscaler/control.pem", KeyFile: "/run/autoscaler/control.key"},
		NodeNatsNKeyFile: "/run/ts-node/node.seed",
		NodeNatsTls:      &control.NatsTlsFiles{CaFile: "/run/ts-node/ca.pem", CertificateFile: "/run/ts-node/node.pem", KeyFile: "/run/ts-node/node.key"},
	}
	arguments, err := autoscalerNodeAgentArguments(settings)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, " ")
	for _, value := range []string{settings.NodeNatsNKeyFile, settings.NodeNatsTls.CaFile,
		settings.NodeNatsTls.CertificateFile, settings.NodeNatsTls.KeyFile} {
		if !strings.Contains(joined, value) {
			t.Fatalf("node arguments omitted %q: %v", value, arguments)
		}
	}
	if strings.Contains(joined, settings.NatsNKeyFile) ||
		strings.Contains(joined, settings.NatsTls.CertificateFile) ||
		strings.Contains(joined, settings.NatsTls.KeyFile) {
		t.Fatalf("autoscaler identity leaked into node arguments: %v", arguments)
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

func TestAutoscalerRoleSnapshotConsumesFreshSchedulerFeed(t *testing.T) {
	now := time.Now()
	role := &autoscalerRole{
		settings: autoscalerRoleSettings{TickInterval: time.Second},
		nodes:    make(map[string]*autoscalerNodeEntry),
	}
	role.handleHeartbeat(&nats.Msg{Subject: "terrascale.node.v1.node-a.heartbeat",
		Data: testAutoscalerHeartbeat(t, "node-a", now.Unix())})
	demandResources, err := autoscaling.NewNodeResources(2<<30, 200, 4)
	if err != nil {
		t.Fatal(err)
	}
	demand, err := autoscaling.NewAllocationDemand("dashboard-a", "dashboard", false, demandResources)
	if err != nil {
		t.Fatal(err)
	}
	feed, err := autoscaling.NewAutoscalerObservationFeed(
		autoscaling.AutoscalerFeedSchemaVersion, now.Unix(),
		[]autoscaling.AllocationDemand{demand}, true, []autoscaling.AutoscalerNodePlacement{
			{NodeId: "node-a", Replicas: nil},
		}, true)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	role.handleObservationFeed(&nats.Msg{Subject: autoscaling.AutoscalerObservationSubject, Data: payload})
	snapshot := role.snapshot(time.Now())
	if len(snapshot.Demand) != 1 || snapshot.Demand[0].RoleId != "dashboard-a" {
		t.Fatalf("snapshot demand did not come from scheduler feed: %+v", snapshot.Demand)
	}
	if !role.replicaHealthReady || len(snapshot.Nodes) != 1 {
		t.Fatalf("complete placement feed was not applied: ready=%v nodes=%+v", role.replicaHealthReady, snapshot.Nodes)
	}
	stale := role.snapshot(now.Add((autoscalerObservationStaleTicks + 1) * time.Second))
	if len(stale.Demand) != 0 || role.replicaHealthReady {
		t.Fatalf("stale scheduler feed must be unavailable: demand=%+v ready=%v", stale.Demand, role.replicaHealthReady)
	}
}

func TestAutoscalerRoleFreshFeedDrivesScaleUpAndDrain(t *testing.T) {
	policy, err := stateful.NewDrainPolicy(1)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := stateful.NewReplicaDrainSafetyEvaluator(policy)
	if err != nil {
		t.Fatal(err)
	}
	role := &autoscalerRole{
		settings:      autoscalerRoleSettings{TickInterval: time.Second},
		replicaDrains: evaluator,
		nodes:         make(map[string]*autoscalerNodeEntry),
	}
	for _, node := range []string{"node-a", "node-b"} {
		role.handleHeartbeat(&nats.Msg{Subject: "terrascale.node.v1." + node + ".heartbeat",
			Data: testAutoscalerHeartbeat(t, node, time.Now().Unix())})
	}
	resources, err := autoscaling.NewNodeResources(2<<30, 200, 128)
	if err != nil {
		t.Fatal(err)
	}
	demand, err := autoscaling.NewAllocationDemand("dashboard-a", "dashboard", false, resources)
	if err != nil {
		t.Fatal(err)
	}
	replicaA, err := stateful.NewReplicaHealth("terrabase", "member-a", true, 0, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	replicaB, err := stateful.NewReplicaHealth("terrabase", "member-b", true, 0, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	feed, err := autoscaling.NewAutoscalerObservationFeed(
		autoscaling.AutoscalerFeedSchemaVersion, time.Now().Unix(),
		[]autoscaling.AllocationDemand{demand}, true, []autoscaling.AutoscalerNodePlacement{
			{NodeId: "node-a", Replicas: []stateful.ReplicaHealth{replicaA}},
			{NodeId: "node-b", Replicas: []stateful.ReplicaHealth{replicaB}},
		}, true)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	role.handleObservationFeed(&nats.Msg{Subject: autoscaling.AutoscalerObservationSubject, Data: payload})

	config, err := autoscaling.NewAutoscalerConfig(1, 3, 20, 30, 1, 1, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	role.engine, err = autoscaling.NewAutoscaler(config, role)
	if err != nil {
		t.Fatal(err)
	}
	role.provisioner = autoscaling.NewStaticNodeProvisioner()
	if err := role.tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(role.provisioner.(*autoscaling.StaticNodeProvisioner).Provisions) != 1 {
		t.Fatalf("fresh demand did not drive scale-up: %+v", role.provisioner)
	}

	// Rebuild the feed as authoritative no-demand evidence and consume it in a
	// second engine: the complete placement health now permits a safe drain.
	feed, err = autoscaling.NewAutoscalerObservationFeed(
		autoscaling.AutoscalerFeedSchemaVersion, role.observationUnixSec+1, nil, true,
		[]autoscaling.AutoscalerNodePlacement{{NodeId: "node-a", Replicas: []stateful.ReplicaHealth{replicaA}},
			{NodeId: "node-b", Replicas: []stateful.ReplicaHealth{replicaB}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	role.handleObservationFeed(&nats.Msg{Subject: autoscaling.AutoscalerObservationSubject, Data: payload})
	role.snapshot(time.Now().Add(2 * time.Second))
	candidate, err := stateful.NewNodeDrainCandidate("node-a", []stateful.ReplicaHealth{replicaA})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := role.EvaluateDrainSafety(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("complete placement feed did not permit a drain: %+v", decision)
	}
}

func TestAutoscalerRoleDefersPlacementWhenTrackedHeartbeatIsStale(t *testing.T) {
	now := time.Now()
	metrics, err := hostagent.NewNodeMetricsSample(1<<30, 0, 100, 0, 128, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	role := &autoscalerRole{
		settings: autoscalerRoleSettings{TickInterval: time.Second},
		nodes: map[string]*autoscalerNodeEntry{"node-a": {
			nodeId: "node-a", state: autoscaling.NodeStateReady, metrics: metrics,
			lastHeartbeat: now.Add(-4 * time.Second), lastHeartbeatUnixSec: now.Unix() - 4,
		}},
	}
	feed, err := autoscaling.NewAutoscalerObservationFeed(
		autoscaling.AutoscalerFeedSchemaVersion, now.Unix(), nil, true,
		[]autoscaling.AutoscalerNodePlacement{{NodeId: "node-a"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	role.handleObservationFeed(&nats.Msg{Subject: autoscaling.AutoscalerObservationSubject, Data: payload})
	role.snapshot(now)
	if role.replicaHealthReady {
		t.Fatal("stale tracked heartbeat must make placement health unavailable")
	}
}

func TestAutoscalerRoleRejectsFreshArrivalWithStaleHeartbeatEvent(t *testing.T) {
	now := time.Now()
	role := &autoscalerRole{
		settings: autoscalerRoleSettings{TickInterval: time.Second},
	}
	// The message arrives now, but its producer timestamp is outside the
	// three-tick freshness window. Arrival time must not refresh old metrics.
	role.handleHeartbeat(&nats.Msg{
		Subject: "terrascale.node.v1.node-a.heartbeat",
		Data:    testAutoscalerHeartbeat(t, "node-a", now.Add(-4*time.Second).Unix()),
	})
	snapshot := role.snapshot(now)
	if len(snapshot.Nodes) != 0 {
		t.Fatalf("stale heartbeat event must not enter the snapshot: %+v", snapshot.Nodes)
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
