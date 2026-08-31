//go:build live_autoscaler

// Package live holds infrastructure-backed smoke tests. This file uses the
// real local process provider and a real ts-node child, so it remains gated by
// both a build tag and explicit environment opt-in.
package live

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/autoscaling"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

const liveAutoscalerTimeout = 60 * time.Second

type liveAllowDrains struct{}

func (liveAllowDrains) EvaluateDrainSafety(
	ctx context.Context,
	candidate stateful.NodeDrainCandidate,
) (stateful.DrainDecision, error) {
	return stateful.NewDrainDecision(true, "live stateless node is safe to drain", nil)
}

// TestAutoscalerLocalProviderLifecycle proves the production loop against a
// material provider. The real engine provisions a real ts-node child through
// CommandProcessSpawner, receives its heartbeat, cordons it over NATS, proves
// the empty node drained, and retires the exact child process. This test does
// not claim OCI evidence; it is the documented single-host provider lane.
func TestAutoscalerLocalProviderLifecycle(t *testing.T) {
	if os.Getenv("TS_ORCH_LIVE_AUTOSCALER") != "1" {
		t.Skip("live autoscaler smoke: set TS_ORCH_LIVE_AUTOSCALER=1 and build with -tags live_autoscaler")
	}
	agentBinary := os.Getenv("TS_ORCH_LIVE_TS_NODE_BINARY")
	if agentBinary == "" || agentBinary[0] != '/' {
		t.Fatal("TS_ORCH_LIVE_TS_NODE_BINARY must name the absolute built ts-node binary")
	}
	uid := uint32(os.Getuid())
	if uid == 0 {
		t.Fatal("the live autoscaler lane must run as a non-root user")
	}

	ctx, cancel := context.WithTimeout(context.Background(), liveAutoscalerTimeout)
	defer cancel()

	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	instance.Start()
	t.Cleanup(func() {
		instance.Shutdown()
		instance.WaitForShutdown()
	})
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded nats server did not become ready")
	}
	connection, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatalf("nats connection: %v", err)
	}
	t.Cleanup(connection.Close)

	heartbeats := make(chan hostagent.NodeHeartbeat, 16)
	subscription, err := connection.Subscribe(
		hostagent.NatsSubjectNodePrefix+".*."+hostagent.NatsSubjectLeafHeartbeat,
		func(message *nats.Msg) {
			var heartbeat hostagent.NodeHeartbeat
			if json.Unmarshal(message.Data, &heartbeat) == nil {
				select {
				case heartbeats <- heartbeat:
				default:
				}
			}
		})
	if err != nil {
		t.Fatalf("heartbeat subscription: %v", err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := connection.Flush(); err != nil {
		t.Fatalf("nats flush: %v", err)
	}

	spawner, err := autoscaling.NewCommandProcessSpawner(5 * time.Second)
	if err != nil {
		t.Fatalf("process spawner: %v", err)
	}
	providerConfig, err := autoscaling.NewLocalProcessProvisionerConfig(
		agentBinary,
		instance.ClientURL(),
		[]string{"--heartbeat-interval", "100ms"},
		uid,
	)
	if err != nil {
		t.Fatalf("local provider config: %v", err)
	}
	provider, err := autoscaling.NewLocalProcessNodeProvisioner(providerConfig, spawner)
	if err != nil {
		t.Fatalf("local provider: %v", err)
	}
	provisioned := false
	retired := false
	t.Cleanup(func() {
		if provisioned && !retired {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			_ = provider.Retire(cleanupCtx, "as-node-1")
		}
	})

	policy, err := autoscaling.NewAutoscalerConfig(1, 2, 20, 30, 1, 2, 1, 1)
	if err != nil {
		t.Fatalf("autoscaler config: %v", err)
	}
	engine, err := autoscaling.NewAutoscaler(policy, liveAllowDrains{})
	if err != nil {
		t.Fatalf("autoscaler: %v", err)
	}
	baselineCapacity := mustLiveNodeResources(t, 1<<30, 100, 64)
	baselineUsage := mustLiveNodeResources(t, 900<<20, 90, 48)
	baseline := mustLiveNodeObservation(
		t, "baseline-node", autoscaling.NodeStateReady, baselineCapacity, baselineUsage, 0)
	demandResources := mustLiveNodeResources(t, 2<<30, 200, 64)
	demand, err := autoscaling.NewAllocationDemand(
		"dashboard-live", "dashboard", false, demandResources)
	if err != nil {
		t.Fatalf("demand: %v", err)
	}

	actions, err := engine.Tick(ctx, autoscaling.AutoscalerSnapshot{
		Nodes: []autoscaling.NodeObservation{baseline}, Demand: []autoscaling.AllocationDemand{demand},
	})
	if err != nil {
		t.Fatalf("scale-up tick: %v", err)
	}
	if len(actions) != 1 || actions[0].Kind() != autoscaling.AutoscalerActionProvisionNode ||
		actions[0].ProvisionRequest().NodeId != "as-node-1" {
		t.Fatalf("scale-up actions = %+v", actions)
	}
	if err := provider.Provision(ctx, actions[0].ProvisionRequest()); err != nil {
		t.Fatalf("real provider provision: %v", err)
	}
	provisioned = true

	heartbeat := waitForLiveHeartbeat(t, ctx, heartbeats, "as-node-1")
	liveCapacity := mustLiveNodeResources(t,
		heartbeat.Metrics.MemoryTotalBytes,
		heartbeat.Metrics.CpuQuotaPercent,
		heartbeat.Metrics.TasksMax)
	liveUsage := mustLiveNodeResources(t,
		heartbeat.Metrics.MemoryUsedBytes,
		heartbeat.Metrics.CpuUsedPercent,
		heartbeat.Metrics.TasksRunning)
	liveNode := mustLiveNodeObservation(
		t, "as-node-1", autoscaling.NodeStateReady, liveCapacity, liveUsage,
		heartbeat.Metrics.PendingAllocations)

	actions, err = engine.Tick(ctx, autoscaling.AutoscalerSnapshot{
		Nodes: []autoscaling.NodeObservation{baseline, liveNode},
	})
	if err != nil {
		t.Fatalf("first scale-down tick: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("first scale-down actions = %+v; sustained headroom is not confirmed", actions)
	}
	actions, err = engine.Tick(ctx, autoscaling.AutoscalerSnapshot{
		Nodes: []autoscaling.NodeObservation{baseline, liveNode},
	})
	if err != nil {
		t.Fatalf("confirmed scale-down tick: %v", err)
	}
	if len(actions) != 2 || actions[0].Kind() != autoscaling.AutoscalerActionCordonNode ||
		actions[1].Kind() != autoscaling.AutoscalerActionDrainNode ||
		actions[0].NodeId() != "as-node-1" || actions[1].NodeId() != "as-node-1" {
		t.Fatalf("scale-down actions = %+v", actions)
	}
	liveCordonNode(t, connection, "as-node-1")
	liveRequireDrained(t, connection, "as-node-1")

	draining := mustLiveNodeObservation(
		t, "as-node-1", autoscaling.NodeStateDraining, liveCapacity,
		mustLiveNodeResources(t, liveUsage.MemoryBytes, liveUsage.CpuPercent, 0), 0)
	actions, err = engine.Tick(ctx, autoscaling.AutoscalerSnapshot{
		Nodes: []autoscaling.NodeObservation{baseline, draining},
	})
	if err != nil {
		t.Fatalf("retire tick: %v", err)
	}
	if len(actions) != 1 || actions[0].Kind() != autoscaling.AutoscalerActionRetireNode ||
		actions[0].NodeId() != "as-node-1" {
		t.Fatalf("retire actions = %+v", actions)
	}
	if err := provider.Retire(ctx, actions[0].NodeId()); err != nil {
		t.Fatalf("real provider retire: %v", err)
	}
	retired = true

}

func mustLiveNodeResources(t *testing.T, memory int64, cpu int, tasks int) autoscaling.NodeResources {
	t.Helper()
	resources, err := autoscaling.NewNodeResources(memory, cpu, tasks)
	if err != nil {
		t.Fatalf("node resources: %v", err)
	}
	return resources
}

func mustLiveNodeObservation(
	t *testing.T,
	nodeID string,
	state autoscaling.NodeState,
	capacity autoscaling.NodeResources,
	usage autoscaling.NodeResources,
	pending int,
) autoscaling.NodeObservation {
	t.Helper()
	observation, err := autoscaling.NewNodeObservation(
		nodeID, state, capacity, usage, pending, nil)
	if err != nil {
		t.Fatalf("node observation: %v", err)
	}
	return observation
}

func waitForLiveHeartbeat(
	t *testing.T,
	ctx context.Context,
	heartbeats <-chan hostagent.NodeHeartbeat,
	nodeID string,
) hostagent.NodeHeartbeat {
	t.Helper()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("heartbeat for %s: %v", nodeID, ctx.Err())
		case heartbeat := <-heartbeats:
			if heartbeat.NodeId.Value == nodeID {
				return heartbeat
			}
		}
	}
}

func liveCordonNode(t *testing.T, connection *nats.Conn, nodeID string) {
	t.Helper()
	identity, err := hostagent.NewNodeId(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := hostagent.NodeCordonSubject(identity)
	if err != nil {
		t.Fatal(err)
	}
	command, err := hostagent.NewCordonCommand("live-cordon", true)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := connection.Request(subject, payload, 5*time.Second)
	if err != nil {
		t.Fatalf("cordon request: %v", err)
	}
	var acknowledgment hostagent.CordonAcknowledgment
	if err := json.Unmarshal(reply.Data, &acknowledgment); err != nil {
		t.Fatalf("cordon acknowledgment: %v", err)
	}
	if !acknowledgment.Cordoned || acknowledgment.NodeId != nodeID {
		t.Fatalf("cordon acknowledgment = %+v", acknowledgment)
	}
}

func liveRequireDrained(t *testing.T, connection *nats.Conn, nodeID string) {
	t.Helper()
	identity, err := hostagent.NewNodeId(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := hostagent.NodeDrainStatusSubject(identity)
	if err != nil {
		t.Fatal(err)
	}
	request, err := hostagent.NewNodeStatusRequest("live-drain-status")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := connection.Request(subject, payload, 5*time.Second)
	if err != nil {
		t.Fatalf("drain-status request: %v", err)
	}
	var report hostagent.DrainStatusReport
	if err := json.Unmarshal(reply.Data, &report); err != nil {
		t.Fatalf("drain-status report: %v", err)
	}
	if !report.Cordoned || !report.Drained || len(report.Allocations) != 0 {
		t.Fatalf("drain-status report = %+v", report)
	}
}

var _ autoscaling.DrainSafetyEvaluator = liveAllowDrains{}
