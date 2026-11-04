package swarmruntime

import (
	"context"

	"errors"
	"net"

	"runtime"

	"testing"
	"time"

	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// This fixture only describes idle nodes; the integration exercises upstream
// certificate exchange, agent registration, control RPCs and persistent Raft.
type nodeIdleExecutor struct{}

func (nodeIdleExecutor) Describe(context.Context) (*api.NodeDescription, error) {
	return &api.NodeDescription{
		Platform:  &api.Platform{OS: "linux", Architecture: runtime.GOARCH},
		Resources: &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 1 << 30},
	}, nil
}
func (nodeIdleExecutor) Configure(context.Context, *api.Node) error         { return nil }
func (nodeIdleExecutor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }
func (nodeIdleExecutor) Controller(*api.Task) (exec.Controller, error) {
	return nil, errors.New("idle integration node does not execute tasks")
}

func nodeFixtureConfig(t *testing.T, hostID, role string) NodeConfig {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return NodeConfig{
		StateDir: t.TempDir(), ListenAddress: address, AdvertiseAddress: address,
		Admission: Admission{Region: "integration", HostID: hostID, InstanceID: "instance-" + hostID, FounderID: "founder", Role: role},
	}
}

func nodeFixtureStart(t *testing.T, ctx context.Context, cfg NodeConfig) *Node {
	t.Helper()
	n, err := StartNode(ctx, cfg, nodeIdleExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeFixtureStop(t, n) })
	return n
}

func nodeFixtureStop(t *testing.T, n *Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := n.Stop(ctx); err != nil {
		t.Errorf("stop actual embedded node: %v", err)
	}
}
