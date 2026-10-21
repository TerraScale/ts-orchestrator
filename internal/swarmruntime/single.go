package swarmruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"

	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// singleHostID is fixed so a hostname change never alters the stored admission.
const singleHostID = "single-host"

// SingleHostAddress is loopback-only: no other node ever joins a single host.
const SingleHostAddress = "127.0.0.1:4242"

// SingleHostSwarmDir holds the certificates, Raft log and control socket.
func SingleHostSwarmDir(stateDir string) string { return filepath.Join(stateDir, "swarm") }

// SingleHostSocket is the root-only SwarmKit control API (api.ControlClient).
// It links to the upstream socket inside the 0700 swarm directory.
func SingleHostSocket(stateDir string) string { return filepath.Join(stateDir, "control.sock") }

// StartSingleHost founds (or reopens) a one-node cluster whose manager is also
// its only Active worker.
func StartSingleHost(ctx context.Context, stateDir string, executor exec.Executor) (*Node, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("single-host state directory must be absolute")
	}
	node, err := StartNode(ctx, NodeConfig{
		StateDir:         SingleHostSwarmDir(stateDir),
		ListenAddress:    SingleHostAddress,
		AdvertiseAddress: SingleHostAddress,
		Admission: Admission{Region: "local", HostID: singleHostID, InstanceID: singleHostID,
			FounderID: singleHostID, Role: "manager"},
	}, executor)
	if err != nil {
		return nil, err
	}
	link := SingleHostSocket(stateDir)
	if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(err, node.Stop(context.WithoutCancel(ctx)))
	}
	if err := os.Symlink(filepath.Join("swarm", "control.sock"), link); err != nil {
		return nil, errors.Join(err, node.Stop(context.WithoutCancel(ctx)))
	}
	if err := removeIngressNetwork(ctx, stateDir); err != nil {
		return nil, errors.Join(err, node.Stop(context.WithoutCancel(ctx)))
	}
	return node, nil
}

// removeIngressNetwork deletes the routing-mesh network SwarmKit creates in
// every fresh cluster. The inert allocator cannot attach the node to it and
// logs a failure on every node update; services here use the host network.
func removeIngressNetwork(ctx context.Context, stateDir string) error {
	client, conn, err := DialSingleHost(stateDir)
	if err != nil {
		return err
	}
	defer conn.Close()
	networks, err := client.ListNetworks(ctx, &api.ListNetworksRequest{})
	if err != nil {
		return err
	}
	for _, network := range networks.Networks {
		if !network.Spec.Ingress {
			continue
		}
		if _, err := client.RemoveNetwork(ctx, &api.RemoveNetworkRequest{NetworkID: network.ID}); err != nil && status.Code(err) != codes.NotFound {
			return err
		}
	}
	return nil
}

// DialSingleHost connects to a single host's control socket over TLS pinned to
// the node's stored root CA. Callers close the returned connection.
func DialSingleHost(stateDir string) (api.ControlClient, *grpc.ClientConn, error) {
	root, err := os.ReadFile(ca.NewConfigPaths(filepath.Join(SingleHostSwarmDir(stateDir), "certificates")).RootCA.Cert)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, nil, errors.New("single-host root CA is not PEM")
	}
	socket := SingleHostSocket(stateDir)
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: ca.ManagerRole, MinVersion: tls.VersionTLS12})
	conn, err := grpc.NewClient("passthrough:///swarm-control", grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
	if err != nil {
		return nil, nil, err
	}
	return api.NewControlClient(conn), conn, nil
}
