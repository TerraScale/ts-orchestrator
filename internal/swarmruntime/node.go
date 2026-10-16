// Package swarmruntime embeds SwarmKit without replacing its task authority.
package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
	"github.com/moby/swarmkit/v2/connectionbroker"
	"github.com/moby/swarmkit/v2/manager"
	swarmnode "github.com/moby/swarmkit/v2/node"
	"github.com/moby/swarmkit/v2/remotes"
)

// Admission is supplied by verified OCI/NetBird membership and Vault delivery.
// FounderID is the durable, fenced regional founder, never a discovery result.
type Admission struct {
	Region         string
	HostID         string
	FounderID      string
	Role           string
	ManagerAddress string
	JoinToken      string
}

// NodeConfig contains derived host paths and admitted network addresses.
type NodeConfig struct {
	StateDir         string
	ListenAddress    string
	AdvertiseAddress string
	Admission        Admission
}

// Node owns the upstream manager, agent, certificates and persistent task store.
type Node struct {
	upstream *swarmnode.Node
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
	role     string
}

type admittedIdentity struct {
	Region    string
	HostID    string
	FounderID string
	Role      string
}

// StartNode starts an admitted node and waits for upstream registration. The
// supplied context governs its lifetime; Stop preserves running containers.
func StartNode(ctx context.Context, cfg NodeConfig, executor exec.Executor) (*Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a := cfg.Admission
	if cfg.StateDir == "" || a.Region == "" || a.HostID == "" || a.FounderID == "" || executor == nil {
		return nil, errors.New("swarm node requires persistent state, admitted identity and executor")
	}
	if a.Role != "manager" && a.Role != "container" && a.Role != "wasm" {
		return nil, errors.New("swarm node requires an admitted manager, container or wasm host role")
	}
	if a.HostID == a.FounderID && (a.Role != "manager" || a.ManagerAddress != "" || a.JoinToken != "") {
		return nil, errors.New("regional founder admission must be a manager without join material")
	}
	for _, address := range []string{cfg.ListenAddress, cfg.AdvertiseAddress} {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return nil, fmt.Errorf("invalid swarm address: %w", err)
		}
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	lock := flock.New(filepath.Join(cfg.StateDir, "node.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("swarm node state is already in use")
	}
	var n *Node
	defer func() {
		if n == nil {
			_ = lock.Unlock()
		}
	}()

	identity := admittedIdentity{Region: a.Region, HostID: a.HostID, FounderID: a.FounderID, Role: a.Role}
	admissionPath := filepath.Join(cfg.StateDir, "admission.json")
	stored, err := os.ReadFile(admissionPath)
	existingAdmission := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if existingAdmission {
		var previous admittedIdentity
		if err := json.Unmarshal(stored, &previous); err != nil {
			return nil, fmt.Errorf("read swarm admission: %w", err)
		}
		if previous != identity {
			return nil, errors.New("swarm admission cannot change an existing node identity or role")
		}
	}

	paths := ca.NewConfigPaths(filepath.Join(cfg.StateDir, "certificates"))
	hasIdentity := true
	for _, path := range []string{paths.RootCA.Cert, paths.Node.Cert, paths.Node.Key} {
		info, err := os.Stat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			hasIdentity = false
		}
	}
	joinAddress, joinToken := "", ""
	if !hasIdentity {
		if a.HostID == a.FounderID {
			// A failed/partial founder initialization requires explicit recovery;
			// a missing certificate must never silently create a second cluster.
			if existingAdmission {
				return nil, errors.New("regional founder identity is missing; restore its persistent state")
			}
			entries, err := os.ReadDir(cfg.StateDir)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if entry.Name() != "node.lock" {
					return nil, errors.New("regional founder requires empty initial state or complete persisted identity")
				}
			}
		} else {
			if _, _, err := net.SplitHostPort(a.ManagerAddress); err != nil {
				return nil, errors.New("joining node requires an admitted manager address")
			}
			if _, err := ca.ParseJoinToken(a.JoinToken); err != nil {
				return nil, errors.New("joining node requires a valid Vault-delivered SwarmKit join token")
			}
			joinAddress, joinToken = a.ManagerAddress, a.JoinToken
		}
	}
	if hasIdentity && a.Role == "manager" {
		entries, err := os.ReadDir(filepath.Join(cfg.StateDir, "raft"))
		if err != nil || len(entries) == 0 {
			return nil, errors.New("manager Raft state is missing; restore its persistent state")
		}
	}
	if !existingAdmission {
		data, err := json.Marshal(identity)
		if err != nil {
			return nil, err
		}
		file, err := os.OpenFile(admissionPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.Write(data)
		if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
			return nil, err
		}
	}
	if hasIdentity || joinAddress != "" {
		rootCA, err := ca.GetLocalRootCA(paths.RootCA)
		peers := remotes.NewRemotes()
		if joinAddress != "" {
			peers.Observe(api.Peer{Addr: joinAddress}, remotes.DefaultObservationWeight)
		}
		broker := connectionbroker.New(peers)
		if errors.Is(err, ca.ErrNoLocalRootCA) && joinAddress != "" {
			rootCA, err = ca.DownloadRootCA(ctx, paths.RootCA, joinToken, broker)
		}
		if err != nil {
			return nil, err
		}
		keys := ca.NewKeyReadWriter(paths.Node, nil, &manager.RaftDEKData{})
		var security *ca.SecurityConfig
		var cleanup func() error
		if hasIdentity {
			security, cleanup, err = ca.LoadSecurityConfig(ctx, rootCA, keys, false)
		} else {
			security, cleanup, err = rootCA.CreateSecurityConfig(ctx, keys, ca.CertificateRequestConfig{Token: joinToken, ConnBroker: broker})
		}
		if err != nil {
			return nil, err
		}
		role := security.ClientTLSCreds.Role()
		if err := cleanup(); err != nil {
			return nil, err
		}
		if (role == ca.ManagerRole) != (a.Role == "manager") {
			err := errors.New("SwarmKit certificate role does not match admitted host role")
			if !hasIdentity {
				err = errors.Join(err, os.Remove(paths.Node.Cert), os.Remove(paths.Node.Key))
			}
			return nil, err
		}
	}
	upstream, err := swarmnode.New(&swarmnode.Config{
		Hostname:           a.HostID,
		StateDir:           cfg.StateDir,
		JoinAddr:           joinAddress,
		JoinToken:          joinToken,
		ListenControlAPI:   filepath.Join(cfg.StateDir, "control.sock"),
		ListenRemoteAPI:    cfg.ListenAddress,
		AdvertiseRemoteAPI: cfg.AdvertiseAddress,
		Executor:           executor,
	})
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	if err := upstream.Start(runCtx); err != nil {
		cancel()
		return nil, err
	}
	n = &Node{upstream: upstream, cancel: cancel, done: make(chan struct{}), role: a.Role}
	go func() {
		n.err = errors.Join(upstream.Err(context.Background()), lock.Unlock())
		close(n.done)
	}()
	select {
	case <-upstream.Ready():
		if (upstream.Manager() != nil) == (a.Role == "manager") {
			return n, nil
		}
		err = errors.New("SwarmKit certificate role does not match admitted host role")
	case <-n.done:
		err = n.err
		if err == nil {
			err = errors.New("swarm node stopped before registration")
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopCancel()
	return nil, errors.Join(err, n.Stop(stopCtx))
}

// ID returns the durable upstream node certificate identity.
func (n *Node) ID() string { return n.upstream.NodeID() }

// RemoteAddress returns the manager's actual bound remote API address.
func (n *Node) RemoteAddress() (string, error) { return n.upstream.RemoteAPIAddr() }

// ControlClient exposes the manager's trusted local control connection. Its
// lifecycle belongs to Node; worker admission never grants control access.
func (n *Node) ControlClient(ctx context.Context) (api.ControlClient, error) {
	if n.role != "manager" || n.upstream.Manager() == nil {
		return nil, errors.New("swarm control API requires an admitted manager")
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for conn := range n.upstream.ListenControlSocket(waitCtx) {
		if conn != nil {
			return api.NewControlClient(conn), nil
		}
	}
	return nil, ctx.Err()
}

// Stop suspends the agent without leaving the swarm or clearing assignments.
func (n *Node) Stop(ctx context.Context) error {
	// Upstream Stop calls agent.Leave; cancel first so workloads survive restart.
	n.cancel()
	select {
	case <-n.done:
		return errors.Join(n.err, n.upstream.Stop(ctx))
	case <-ctx.Done():
		return ctx.Err()
	}
}
