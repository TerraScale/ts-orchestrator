package hostagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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
