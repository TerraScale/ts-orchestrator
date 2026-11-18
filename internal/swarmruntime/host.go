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
	"strconv"
	"time"

	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/opencontainers/go-digest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const SwarmPort = 4242

func FoundingAdmission(hostname, instanceID string) Admission {
	return Admission{Region: "local", HostID: hostname, InstanceID: instanceID, FounderID: hostname, Role: "manager"}
}

func JoiningAdmission(hostname, instanceID, manager, token string) (Admission, error) {
	parsed, err := ca.ParseJoinToken(token)
	if err != nil {
		return Admission{}, fmt.Errorf("join token: %w", err)
	}
	return Admission{Region: "local", HostID: hostname, InstanceID: instanceID, FounderID: parsed.RootDigest.String(), Role: "container",
		ManagerAddress: manager, JoinToken: token}, nil
}

func SwarmAddresses(privateIP string) (listen, advertise string) {
	port := strconv.Itoa(SwarmPort)
	if privateIP == "" {
		loopback := net.JoinHostPort("127.0.0.1", port)
		return loopback, loopback
	}
	return net.JoinHostPort("0.0.0.0", port), net.JoinHostPort(privateIP, port)
}

// StoredAdmission returns the admission the host started with before, so a
// restart keeps its role and identity without Vault.
func StoredAdmission(stateDir string) (Admission, bool, error) {
	stored, found, err := readAdmission(stateDir)
	if err != nil || !found {
		return Admission{}, found, err
	}
	if err := reconcileAdmissionRole(context.Background(), SwarmDir(stateDir), &stored); err != nil {
		return Admission{}, false, err
	}
	return stored.admission(), true, nil
}

func ReadAdmission(stateDir string) (Admission, bool, error) {
	stored, found, err := readAdmission(stateDir)
	return stored.admission(), found, err
}

func readAdmission(stateDir string) (admittedIdentity, bool, error) {
	data, err := os.ReadFile(filepath.Join(SwarmDir(stateDir), "admission.json"))
	if errors.Is(err, os.ErrNotExist) {
		return admittedIdentity{}, false, nil
	}
	if err != nil {
		return admittedIdentity{}, false, err
	}
	var stored admittedIdentity
	if err := json.Unmarshal(data, &stored); err != nil {
		return admittedIdentity{}, false, fmt.Errorf("read swarm admission: %w", err)
	}
	return stored, true, nil
}

func (i admittedIdentity) admission() Admission {
	return Admission{Region: i.Region, HostID: i.HostID, InstanceID: i.InstanceID, FounderID: i.FounderID, Role: i.Role}
}

func SwarmDir(stateDir string) string { return filepath.Join(stateDir, "swarm") }

func (a Admission) BelongsTo(hostname, instanceID string) bool {
	return a.HostID == hostname && a.InstanceID == instanceID
}

func ClusterRoot(stateDir string) (digest.Digest, error) {
	root, err := ca.GetLocalRootCA(ca.NewConfigPaths(filepath.Join(SwarmDir(stateDir), "certificates")).RootCA)
	if err != nil {
		return "", fmt.Errorf("read stored cluster root: %w", err)
	}
	return root.Digest, nil
}

func SetAsideSwarm(stateDir string, at time.Time) (string, error) {
	lock := flock.New(filepath.Join(SwarmDir(stateDir), "node.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return "", err
	}
	if !locked {
		return "", errors.New("swarm node state is already in use")
	}
	defer lock.Unlock()
	aside := filepath.Join(stateDir, "set-aside", "swarm-"+at.UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(filepath.Dir(aside), 0o700); err != nil {
		return "", err
	}
	return aside, os.Rename(SwarmDir(stateDir), aside)
}

func ControlSocket(stateDir string) string { return filepath.Join(stateDir, "control.sock") }

func StartHost(ctx context.Context, stateDir string, executor exec.Executor, listen, advertise string, admission Admission) (*Node, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("node state directory must be absolute")
	}
	node, err := StartNode(ctx, NodeConfig{
		StateDir: SwarmDir(stateDir), ListenAddress: listen, AdvertiseAddress: advertise, Admission: admission,
	}, executor)
	if err != nil {
		return nil, err
	}
	link := ControlSocket(stateDir)
	if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(err, node.Stop(context.WithoutCancel(ctx)))
	}
	if err := os.Symlink(filepath.Join("swarm", "control.sock"), link); err != nil {
		return nil, errors.Join(err, node.Stop(context.WithoutCancel(ctx)))
	}
	if !node.IsManager() {
		return node, nil
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
	client, conn, err := DialControl(stateDir)
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
	paths := ca.NewConfigPaths(filepath.Join(SwarmDir(stateDir), "certificates"))
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
	client, conn, err := DialControl(stateDir)
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

func DialControl(stateDir string) (api.ControlClient, *grpc.ClientConn, error) {
	root, err := os.ReadFile(ca.NewConfigPaths(filepath.Join(SwarmDir(stateDir), "certificates")).RootCA.Cert)
	if err != nil {
		return nil, nil, err
	}
	return DialControlWithCA(stateDir, root)
}

func DialControlWithCA(stateDir string, root []byte) (api.ControlClient, *grpc.ClientConn, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, nil, errors.New("node root CA is not PEM")
	}
	socket := ControlSocket(stateDir)
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: ca.ManagerRole, MinVersion: tls.VersionTLS12})
	conn, err := grpc.NewClient("passthrough:///swarm-control", grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
	if err != nil {
		return nil, nil, err
	}
	return localControl{ControlClient: api.NewControlClient(conn), state: stateDir}, conn, nil
}

func LocalNodeID(ctx context.Context, stateDir string) (string, error) {
	certificate, err := nodeCertificate(ctx, SwarmDir(stateDir))
	if err != nil {
		return "", err
	}
	return certificate.Subject.CommonName, nil
}
