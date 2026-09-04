package hostagent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// TestAgentServesAndReconcilesFromTheManifest asserts the composed agent:
// it serves the RPC subjects, runs the manifest watch, and shuts down
// cleanly on context cancellation.
func TestAgentServesAndReconcilesFromTheManifest(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifestPath, mustJSON(t, HostManifest{
		Components: []ComponentSpec{spec},
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	connection := newFakeNatsConnection()
	agent, err := NewHostAgent(HostAgentConfig{
		NodeId:            NodeId{Value: "gru-1"},
		Connection:        connection,
		Lifecycle:         harness.lifecycle,
		Facts:             harness.factsSource(t),
		ManifestPath:      manifestPath,
		ReconcileInterval: 10 * time.Millisecond,
		HeartbeatInterval: 10 * time.Millisecond,
		Now:               func() time.Time { return time.Unix(1756900000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := agent.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !harness.systemd.isActive(UnitName("terrabase")) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !harness.systemd.isActive(UnitName("terrabase")) {
		t.Fatal("agent never reconciled the manifest to a running unit")
	}
	if heartbeats := connection.heartbeatPayloads(t); len(heartbeats) == 0 {
		t.Fatal("agent never published a heartbeat")
	}
	cancel()
	select {
	case <-agent.Completion():
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not complete after cancellation")
	}
}

// TestAgentReconnectsAfterEmbeddedBrokerRestart proves a transient restart
// of the colocated NATS process does not leave ts-node alive but permanently
// unsubscribed.
func TestAgentReconnectsAfterEmbeddedBrokerRestart(t *testing.T) {
	instance := startHostAgentTestNats(t, -1)
	port := instance.Addr().(*net.TCPAddr).Port
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifestPath, mustJSON(t, HostManifest{Components: []ComponentSpec{spec}}), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := NewHostAgent(HostAgentConfig{
		NodeId: NodeId{Value: "gru-1"}, NatsURL: instance.ClientURL(), ConnectTimeout: time.Second,
		Lifecycle: harness.lifecycle, Facts: harness.factsSource(t), ManifestPath: manifestPath,
		ReconcileInterval: 20 * time.Millisecond, HeartbeatInterval: 20 * time.Millisecond,
		Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := agent.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	assertAgentStatusReply(t, instance.ClientURL(), "before-restart")

	instance.Shutdown()
	instance.WaitForShutdown()
	restarted := startHostAgentTestNats(t, port)
	t.Cleanup(restarted.Shutdown)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := requestAgentStatus(restarted.ClientURL(), "after-restart"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not resubscribe after the embedded broker restarted")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func startHostAgentTestNats(t *testing.T, port int) *server.Server {
	t.Helper()
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: port, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go instance.Start()
	if !instance.ReadyForConnections(5 * time.Second) {
		instance.Shutdown()
		t.Fatal("test NATS server did not become ready")
	}
	return instance
}

func assertAgentStatusReply(t *testing.T, url, commandId string) {
	t.Helper()
	if err := requestAgentStatus(url, commandId); err != nil {
		t.Fatal(err)
	}
}

func requestAgentStatus(url, commandId string) error {
	connection, err := nats.Connect(url, nats.Timeout(250*time.Millisecond), nats.MaxReconnects(0))
	if err != nil {
		return err
	}
	defer connection.Close()
	payload, err := json.Marshal(NodeStatusRequest{CommandId: commandId})
	if err != nil {
		return err
	}
	message, err := connection.Request(
		"ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain-status",
		payload, 250*time.Millisecond)
	if err != nil {
		return err
	}
	var report NodeStatusReport
	if err := json.Unmarshal(message.Data, &report); err != nil {
		return err
	}
	if report.CommandId != commandId || report.NodeId != "gru-1" {
		return &InvalidDataError{Message: "the status response identity is invalid"}
	}
	return nil
}

// TestNewHostAgentValidatesConfiguration asserts the composition's trust
// boundary.
func TestNewHostAgentValidatesConfiguration(t *testing.T) {
	harness := newTestHarness(t)
	base := HostAgentConfig{
		NodeId:            NodeId{Value: "gru-1"},
		Connection:        newFakeNatsConnection(),
		Lifecycle:         harness.lifecycle,
		Facts:             harness.factsSource(t),
		ManifestPath:      "/etc/terrascale/manifest.json",
		ReconcileInterval: time.Second,
		HeartbeatInterval: time.Second,
		Now:               time.Now,
	}
	if _, err := NewHostAgent(base); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	mutated := base
	mutated.NodeId = NodeId{Value: "BAD"}
	if _, err := NewHostAgent(mutated); err == nil {
		t.Fatal("invalid node id accepted")
	}
	mutated = base
	mutated.Connection = nil
	mutated.NatsURL = "nats://127.0.0.1:4222"
	mutated.ConnectTimeout = time.Second
	if _, err := NewHostAgent(mutated); err != nil {
		t.Fatalf("dial configuration rejected: %v", err)
	}
	mutated.Connection = newFakeNatsConnection()
	if _, err := NewHostAgent(mutated); err == nil {
		t.Fatal("both connection and URL accepted")
	}
}
