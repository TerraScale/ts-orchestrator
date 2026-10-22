package swarmruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
	"github.com/moby/swarmkit/v2/manager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// singleHostID is fixed so a hostname change never alters the stored admission.
const singleHostID = "single-host"

// SingleHostAddress serves a host outside OCI, where no other node joins. An
// OCI founder listens on SwarmPort of every interface and advertises its
// private VCN address.
const SingleHostAddress = "127.0.0.1:4242"

// SwarmPort is the manager's remote API; the host NSG admits it inside the VCN only.
const SwarmPort = 4242

// FounderAdmission is the fixed identity of the host that founds its region's
// cluster; a hostname change never alters the stored admission.
func FounderAdmission() Admission {
	return Admission{Region: "local", HostID: singleHostID, InstanceID: singleHostID, FounderID: singleHostID, Role: "manager"}
}

// JoinerAdmission is a container worker that joins the founder's cluster with
// Vault-delivered join material.
func JoinerAdmission(hostname, instanceID, manager, token string) Admission {
	return Admission{Region: "local", HostID: hostname, InstanceID: instanceID, FounderID: singleHostID, Role: "container",
		ManagerAddress: manager, JoinToken: token}
}

// StoredAdmission returns the admission the host started with before, so a
// restart keeps its role and identity without Vault.
func StoredAdmission(stateDir string) (Admission, bool, error) {
	data, err := os.ReadFile(filepath.Join(SingleHostSwarmDir(stateDir), "admission.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Admission{}, false, nil
	}
	if err != nil {
		return Admission{}, false, err
	}
	var stored admittedIdentity
	if err := json.Unmarshal(data, &stored); err != nil {
		return Admission{}, false, fmt.Errorf("read swarm admission: %w", err)
	}
	return Admission{Region: stored.Region, HostID: stored.HostID, InstanceID: stored.InstanceID, FounderID: stored.FounderID, Role: stored.Role}, true, nil
}

// SingleHostSwarmDir holds the certificates, Raft log and control socket.
func SingleHostSwarmDir(stateDir string) string { return filepath.Join(stateDir, "swarm") }

// SingleHostSocket is the root-only SwarmKit control API (api.ControlClient).
// It links to the upstream socket inside the 0700 swarm directory.
func SingleHostSocket(stateDir string) string { return filepath.Join(stateDir, "control.sock") }

// StartSingleHost founds (or reopens) the region's cluster, whose manager is
// also an Active worker, or joins it as a worker (a JoinerAdmission). A
// founder that advertised another address before moves its Raft member
// address to advertise, so workers reach it there.
func StartSingleHost(ctx context.Context, stateDir string, executor exec.Executor, listen, advertise string, admission Admission) (*Node, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("single-host state directory must be absolute")
	}
	node, err := StartNode(ctx, NodeConfig{
		StateDir: SingleHostSwarmDir(stateDir), ListenAddress: listen, AdvertiseAddress: advertise, Admission: admission,
	}, executor)
	if err != nil {
		return nil, err
	}
	if admission.Role != "manager" {
		return node, nil // a worker has no control socket
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
	if err := moveRaftAddress(ctx, stateDir, node.ID(), advertise); err != nil {
		// The manager keeps serving its own tasks; only joining workers wait for the next start.
		slog.WarnContext(ctx, "swarm manager address unchanged", "error", err)
	}
	return node, nil
}

// moveRaftAddress re-registers the manager's Raft member at advertise.
// SwarmKit keeps a restarted manager's stored member address (BindRemote sets
// only the address a new member joins with), and workers learn their manager
// list from it. A Raft join from the member's own node identity updates the
// address in place: same cluster, Raft log and services. A restart replays
// its own address change as a no-op until a snapshot holds it, so every
// start re-checks.
func moveRaftAddress(ctx context.Context, stateDir, nodeID, advertise string) error {
	client, conn, err := DialSingleHost(stateDir)
	if err != nil {
		return err
	}
	defer conn.Close()
	self, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		return err
	}
	if self.Node.ManagerStatus == nil || self.Node.ManagerStatus.Addr == advertise {
		return nil
	}
	paths := ca.NewConfigPaths(filepath.Join(SingleHostSwarmDir(stateDir), "certificates"))
	root, err := ca.GetLocalRootCA(paths.RootCA)
	if err != nil {
		return err
	}
	security, cleanup, err := ca.LoadSecurityConfig(ctx, root, ca.NewKeyReadWriter(paths.Node, nil, &manager.RaftDEKData{}), false)
	if err != nil {
		return err
	}
	defer cleanup()
	remote, err := grpc.NewClient("passthrough:///"+advertise, grpc.WithTransportCredentials(security.ClientTLSCreds))
	if err != nil {
		return err
	}
	defer remote.Close()
	joinCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := api.NewRaftMembershipClient(remote).Join(joinCtx, &api.JoinRequest{Addr: advertise}); err != nil {
		return fmt.Errorf("move swarm manager address from %s to %s: %w", self.Node.ManagerStatus.Addr, advertise, err)
	}
	return nil
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
