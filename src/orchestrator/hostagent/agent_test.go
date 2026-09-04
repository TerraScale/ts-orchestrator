// This file tests the host agent composition: configuration validation,
// serving through a wired fake connection, context-driven shutdown, and
// graceful close.
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func agentTestConfig(t *testing.T, connection NatsConnection) HostAgentConfig {
	t.Helper()
	return HostAgentConfig{
		NodeId:            executorTestNodeId(t),
		Connection:        connection,
		Systemd:           &fakeNativeAdapter{observation: runningSystemdObservation()},
		Metrics:           defaultMetricsForTest(),
		HeartbeatInterval: 30 * time.Second,
		Now:               fixedTestClock,
	}
}

func TestNewHostAgentValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(config *HostAgentConfig)
		wantParam string
	}{
		{
			name:      "missing node id",
			mutate:    func(c *HostAgentConfig) { c.NodeId = NodeId{} },
			wantParam: "value",
		},
		{
			name:      "both connection and url",
			mutate:    func(c *HostAgentConfig) { c.NatsURL = "nats://localhost:4222" },
			wantParam: "Connection",
		},
		{
			name:      "neither connection nor url",
			mutate:    func(c *HostAgentConfig) { c.Connection = nil },
			wantParam: "Connection",
		},
		{
			name: "dial options with wired connection",
			mutate: func(c *HostAgentConfig) {
				c.NatsOptions = []nats.Option{func(*nats.Options) error { return nil }}
			},
			wantParam: "NatsOptions",
		},
		{
			name: "url without connect timeout",
			mutate: func(c *HostAgentConfig) {
				c.Connection = nil
				c.NatsURL = "nats://localhost:4222"
			},
			wantParam: "ConnectTimeout",
		},
		{
			name:      "missing systemd adapter",
			mutate:    func(c *HostAgentConfig) { c.Systemd = nil },
			wantParam: "Systemd",
		},
		{
			name:      "missing metrics source",
			mutate:    func(c *HostAgentConfig) { c.Metrics = nil },
			wantParam: "Metrics",
		},
		{
			name:      "non positive heartbeat interval",
			mutate:    func(c *HostAgentConfig) { c.HeartbeatInterval = 0 },
			wantParam: "HeartbeatInterval",
		},
		{
			name:      "missing clock",
			mutate:    func(c *HostAgentConfig) { c.Now = nil },
			wantParam: "Now",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := agentTestConfig(t, newFakeNatsConnection())
			test.mutate(&config)
			if _, err := NewHostAgent(config); err == nil {
				t.Fatal("expected a configuration error")
			} else if !errorsAsParam(err, test.wantParam) {
				t.Fatalf("error %v does not reference param %s", err, test.wantParam)
			}
		})
	}
}

func TestHostAgentServesThroughTheWiredConnection(t *testing.T) {
	connection := newFakeNatsConnection()
	agent, err := NewHostAgent(agentTestConfig(t, connection))
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })

	if agent.NodeId().Value != "gru-node-1" {
		t.Fatalf("node id = %q", agent.NodeId().Value)
	}
	if agent.Executor() == nil {
		t.Fatal("the agent must expose its executor")
	}
	if len(connection.subscriptions) != 6 {
		t.Fatalf("the agent must serve all six subjects: %v", connection.subscriptions)
	}
	if published := connection.publicationsOn("terrascale.node.v1.gru-node-1.heartbeat"); len(published) != 1 {
		t.Fatalf("the agent must publish its first heartbeat, got %d", len(published))
	}

	plan := executorTestPlan(t, runtime.AdmittedRoleAutoscaler, runtime.RuntimeDriverNativeSystemd, "gru-orchestrator-1")
	command := executorTestCommand(t, plan, "cmd-agent-1")
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatalf("command wire: %v", err)
	}
	reply := connection.request("terrascale.node.v1.gru-node-1.converge", payload)
	var receipt ConvergeReceipt
	if err := json.Unmarshal(reply, &receipt); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if !receipt.Accepted || receipt.CommandId != "cmd-agent-1" {
		t.Fatalf("receipt = %+v", receipt)
	}

	if err := agent.Start(context.Background()); err == nil {
		t.Fatal("starting twice must be rejected")
	}
}

func TestHostAgentClosesGracefullyOnce(t *testing.T) {
	connection := newFakeNatsConnection()
	agent, err := NewHostAgent(agentTestConfig(t, connection))
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	if err := agent.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("close must be idempotent: %v", err)
	}
	_, drains, closes := connection.counts()
	// The transport owns nothing here: the caller wired the connection, so the
	// agent drains it but never closes it.
	if drains != 1 || closes != 0 {
		t.Fatalf("drains = %d, closes = %d", drains, closes)
	}
	select {
	case <-agent.Completion():
	default:
		t.Fatal("a closed agent must complete")
	}
}

func TestHostAgentClosesWhenItsContextIsCancelled(t *testing.T) {
	connection := newFakeNatsConnection()
	agent, err := NewHostAgent(agentTestConfig(t, connection))
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	cancel()

	select {
	case <-agent.Completion():
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the start context must close the agent")
	}
	_, drains, _ := connection.counts()
	if drains != 1 {
		t.Fatalf("the context-driven close must drain the transport, got %d drains", drains)
	}
}

func TestHostAgentRejectsNilStartContext(t *testing.T) {
	agent, err := NewHostAgent(agentTestConfig(t, newFakeNatsConnection()))
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	if err := agent.Start(nil); err == nil {
		t.Fatal("a nil start context must be rejected")
	}
}

func TestHostAgentRejectsStartAfterClose(t *testing.T) {
	agent, err := NewHostAgent(agentTestConfig(t, newFakeNatsConnection()))
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var operationError *InvalidOperationError
	if err := agent.Start(context.Background()); !errors.As(err, &operationError) {
		t.Fatalf("start after close must be rejected, got %v", err)
	}
}
