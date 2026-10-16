package swarmruntime

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestNodeIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	founderCfg := nodeFixtureConfig(t, "founder", "manager")
	founder := nodeFixtureStart(t, ctx, founderCfg)
	founderID := founder.ID()
	client, err := founder.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatalf("list actual cluster: %v, %v", clusters, err)
	}
	cluster := clusters.Clusters[0]
	created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "node-persistence-proof"},
		Task: api.TaskSpec{Runtime: &api.TaskSpec_Container{Container: &api.ContainerSpec{
			Image: "example.invalid/proof@sha256:" + strings.Repeat("0", 64),
		}}},
		Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartNode(ctx, founderCfg, nodeIdleExecutor{}); err == nil {
		t.Fatal("concurrent node acquired the same persistent identity")
	}

	workerCfg := nodeFixtureConfig(t, "worker", "container")
	workerCfg.Admission.ManagerAddress, err = founder.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	workerCfg.Admission.JoinToken = cluster.RootCA.JoinTokens.Worker
	worker := nodeFixtureStart(t, ctx, workerCfg)
	workerID := worker.ID()
	if _, err := worker.ControlClient(ctx); err == nil {
		t.Fatal("worker received manager control access")
	}
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil || len(nodes.Nodes) != 2 {
		t.Fatalf("actual registered nodes: %v, %v", nodes, err)
	}
	nodeFixtureCertificate(t, workerCfg.StateDir, workerID, cluster.RootCA.CACert)

	// A manager token delivered to a worker must fail before any manager starts.
	escalationCfg := nodeFixtureConfig(t, "escalation", "container")
	escalationCfg.Admission.ManagerAddress = workerCfg.Admission.ManagerAddress
	escalationCfg.Admission.JoinToken = cluster.RootCA.JoinTokens.Manager
	if _, err := StartNode(ctx, escalationCfg, nodeIdleExecutor{}); err == nil || !strings.Contains(err.Error(), "certificate role") {
		t.Fatalf("manager-token worker admission: %v", err)
	}
	if _, err := os.Stat(filepath.Join(escalationCfg.StateDir, "control.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unauthorized manager started control API: %v", err)
	}
	if _, err := os.Stat(filepath.Join(escalationCfg.StateDir, "raft")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unauthorized manager started Raft: %v", err)
	}
	if _, err := os.Stat(filepath.Join(escalationCfg.StateDir, "certificates", "swarm-node.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("worker retained a manager private key: %v", err)
	}

	nodeFixtureStop(t, worker)
	workerCfg.Admission.ManagerAddress, workerCfg.Admission.JoinToken = "", ""
	worker = nodeFixtureStart(t, ctx, workerCfg)
	if worker.ID() != workerID {
		t.Fatalf("worker identity changed across restart: %s -> %s", workerID, worker.ID())
	}
	nodeFixtureStop(t, worker)
	nodeFixtureStop(t, founder)
	founder = nodeFixtureStart(t, ctx, founderCfg)
	if founder.ID() != founderID {
		t.Fatalf("founder identity changed across restart: %s -> %s", founderID, founder.ID())
	}
	client, err = founder.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err = client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 || clusters.Clusters[0].ID != cluster.ID {
		t.Fatalf("cluster identity changed across restart: %v, %v", clusters, err)
	}
	service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID})
	if err != nil || service.Service.Spec.Annotations.Name != "node-persistence-proof" {
		t.Fatalf("Raft service did not survive restart: %v, %v", service, err)
	}
	nodeFixtureStop(t, founder)
	raftPath := filepath.Join(founderCfg.StateDir, "raft")
	if err := os.Rename(raftPath, raftPath+"-hold"); err != nil {
		t.Fatal(err)
	}
	if _, err := StartNode(ctx, founderCfg, nodeIdleExecutor{}); err == nil {
		t.Fatal("missing Raft state silently founded another cluster")
	}
	if err := os.Rename(raftPath+"-hold", raftPath); err != nil {
		t.Fatal(err)
	}

	missingDiscovery := nodeFixtureConfig(t, "unjoined", "container")
	if _, err := StartNode(ctx, missingDiscovery, nodeIdleExecutor{}); err == nil {
		t.Fatal("empty discovery let a worker found a cluster")
	}
	changedAdmission := workerCfg
	changedAdmission.Admission.FounderID = "worker"
	changedAdmission.Admission.Role = "manager"
	if _, err := StartNode(ctx, changedAdmission, nodeIdleExecutor{}); err == nil {
		t.Fatal("persisted worker changed its admission to founder")
	}
	if err := os.Remove(filepath.Join(founderCfg.StateDir, "certificates", "swarm-node.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := StartNode(ctx, founderCfg, nodeIdleExecutor{}); err == nil {
		t.Fatal("missing founder identity silently founded another cluster")
	}
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

func nodeFixtureCertificate(t *testing.T, stateDir, nodeID string, root []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, "certificates", "swarm-node.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("missing upstream certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		t.Fatal("invalid upstream root CA")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify persisted worker identity: %v", err)
	}
	if cert.Subject.CommonName != nodeID || len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "swarm-worker" {
		t.Fatalf("unexpected persisted worker identity: %v", cert.Subject)
	}
}
