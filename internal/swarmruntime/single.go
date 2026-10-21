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
	"google.golang.org/grpc/credentials"
)

// singleHostID is fixed so a hostname change never alters the stored admission.
const singleHostID = "single-host"

// SingleHostAddress is loopback-only: no other node ever joins a single host.
const SingleHostAddress = "127.0.0.1:4242"

// SingleHostSwarmDir holds the certificates, Raft log and control socket.
func SingleHostSwarmDir(stateDir string) string { return filepath.Join(stateDir, "swarm") }

// SingleHostSocket is the root-only SwarmKit control API (api.ControlClient).
func SingleHostSocket(stateDir string) string {
	return filepath.Join(SingleHostSwarmDir(stateDir), "control.sock")
}

// StartSingleHost founds (or reopens) a one-node cluster whose manager is also
// its only Active worker.
func StartSingleHost(ctx context.Context, stateDir string, executor exec.Executor) (*Node, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("single-host state directory must be absolute")
	}
	return StartNode(ctx, NodeConfig{
		StateDir:         SingleHostSwarmDir(stateDir),
		ListenAddress:    SingleHostAddress,
		AdvertiseAddress: SingleHostAddress,
		Admission: Admission{Region: "local", HostID: singleHostID, InstanceID: singleHostID,
			FounderID: singleHostID, Role: "manager"},
	}, executor)
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
