package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

const rootBrokerObservationSocket = "/run/terrascale-orchestrator/broker-observations.sock"
const rootBrokerObservationMaxFrame = 128 << 10

type rootBrokerReader struct {
	ctx       context.Context
	replicas  int
	transport *natscell.Runtime
	conn      *nats.Conn
	mu        sync.Mutex
	binding   string
}

func openControllerBrokerNative(ctx context.Context, cfg Config, transport *natscell.Runtime) (controllerBrokerNative, error) {
	if ctx == nil || transport == nil || transport.Conn() == nil {
		return nil, rootoci.ErrUnavailable
	}
	if cfg.NATS.Replicas < 1 || cfg.NATS.Replicas > 5 || cfg.NATS.Replicas%2 == 0 {
		return nil, errors.New("regional replicas must be 1, 3, or 5")
	}
	reader := &rootBrokerReader{ctx: ctx, replicas: cfg.NATS.Replicas, transport: transport, conn: transport.Conn()}
	if _, err := reader.ObserveCluster(); err != nil {
		return nil, err
	}
	return reader, nil
}

func (reader *rootBrokerReader) ObserveCluster() (natscell.ClusterObservation, error) {
	response, err := reader.invoke(nil, rootBrokerCluster, 2*time.Second)
	if response.Cluster == nil {
		return natscell.ClusterObservation{}, err
	}
	return response.Cluster.Observation, err
}

func (reader *rootBrokerReader) Meta() (natscell.MetaView, error) {
	response, err := reader.invoke(nil, rootBrokerMeta, 2*time.Second)
	if err != nil {
		return natscell.MetaView{}, err
	}
	return *response.Meta, nil
}

func (reader *rootBrokerReader) Observe(ctx context.Context) (observability.NATSView, error) {
	response, err := reader.invoke(ctx, rootBrokerMetrics, 30*time.Second)
	if err != nil {
		return observability.NATSView{}, err
	}
	return *response.Metrics, nil
}

func (reader *rootBrokerReader) LocalStoreUsedBytes(ctx context.Context) (uint64, error) {
	response, err := reader.invoke(ctx, rootBrokerStore, 30*time.Second)
	if err != nil {
		return 0, err
	}
	return *response.Store, nil
}

func (reader *rootBrokerReader) StreamHealth(ctx context.Context) ([]natscell.StreamState, error) {
	response, err := reader.invoke(ctx, rootBrokerStreams, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return *response.Streams, nil
}

func (reader *rootBrokerReader) ReadControllerAccount(ctx context.Context) (natscell.ControllerAccountView, error) {
	response, err := reader.invoke(ctx, rootBrokerAccount, 30*time.Second)
	if err != nil {
		return natscell.ControllerAccountView{}, err
	}
	return *response.Account, nil
}

func (reader *rootBrokerReader) transportReady() bool {
	return reader != nil && reader.ctx != nil && reader.ctx.Err() == nil && reader.transport != nil &&
		reader.conn != nil && reader.transport.Conn() == reader.conn && reader.transport.Ready()
}

func (reader *rootBrokerReader) Ready() bool {
	if !reader.transportReady() {
		return false
	}
	response, err := reader.invoke(nil, rootBrokerCluster, 2*time.Second)
	return err == nil && response.Cluster.QuorumReady && reader.transportReady()
}

func (reader *rootBrokerReader) FullClusterReady(replicas int) bool {
	if reader == nil || replicas != reader.replicas || !reader.transportReady() {
		return false
	}
	response, err := reader.invoke(nil, rootBrokerCluster, 2*time.Second)
	return err == nil && response.Cluster.FullReady && reader.transportReady()
}

func (reader *rootBrokerReader) WaitForCluster(parent context.Context, replicas int) error {
	if reader == nil || reader.ctx == nil || parent == nil {
		return rootoci.ErrUnavailable
	}
	if replicas != reader.replicas {
		return errors.New("regional replicas differ from the native broker reader")
	}
	ctx, cancel := rootBrokerReaderContext(parent, reader.ctx)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := reader.invoke(ctx, rootBrokerCluster, 30*time.Second)
		if errors.Is(err, natscell.ErrEmbeddedServerStopped) {
			return err
		}
		if err == nil && response.Cluster.QuorumReady && reader.transportReady() && reader.transport.JetStream() != nil {
			probeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Second)
			_, probeErr := reader.transport.JetStream().AccountInfo(probeCtx)
			probeCancel()
			if probeErr == nil && ctx.Err() == nil && reader.transportReady() {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-ticker.C:
		}
	}
}

func rootBrokerReaderContext(parent, original context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(original, func() { cancel(context.Cause(original)) })
	if original.Err() != nil {
		cancel(context.Cause(original))
	}
	// Retain the original deadline as well as its cancellation cause.
	if deadline, ok := original.Deadline(); ok {
		bounded, deadlineCancel := context.WithDeadline(ctx, deadline)
		return bounded, func() { deadlineCancel(); stop(); cancel(context.Canceled) }
	}
	return ctx, func() { stop(); cancel(context.Canceled) }
}

func (reader *rootBrokerReader) invoke(parent context.Context, operation rootBrokerOperation, timeout time.Duration) (response rootBrokerResponse, err error) {
	if reader == nil || reader.ctx == nil {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	if parent == nil {
		parent = reader.ctx
	}
	merged, mergeCancel := rootBrokerReaderContext(parent, reader.ctx)
	defer mergeCancel()
	ctx, cancel := context.WithTimeout(merged, timeout)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			response, err = rootBrokerResponse{}, context.Cause(ctx)
		} else if reader.ctx.Err() != nil {
			response, err = rootBrokerResponse{}, context.Cause(reader.ctx)
		}
	}()
	if ctx.Err() != nil {
		return rootBrokerResponse{}, context.Cause(ctx)
	}
	wire, err := json.Marshal(rootBrokerRequest{Operation: operation})
	if err != nil {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	connection, err := new(net.Dialer).DialContext(ctx, "unix", rootBrokerObservationSocket)
	if err != nil {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	defer connection.Close()
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		return rootBrokerResponse{}, rootoci.ErrUnauthorized
	}
	peer, err := rootociwire.PeerCredential(socket)
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		return rootBrokerResponse{}, rootoci.ErrUnauthorized
	}
	if err := reader.verify(socket); err != nil {
		return rootBrokerResponse{}, err
	}
	deadline, _ := ctx.Deadline()
	if socket.SetDeadline(deadline) != nil {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	if rootociwire.WriteBoundedFrame(socket, wire, rootBrokerObservationMaxFrame) != nil {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	reply, err := rootociwire.ReadBoundedFrame(socket, rootBrokerObservationMaxFrame)
	if err != nil {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	response, err = decodeRootBrokerResponse(reply, operation)
	if err := reader.verify(socket); err != nil {
		return rootBrokerResponse{}, err
	}
	return response, err
}

func (reader *rootBrokerReader) verify(socket *net.UnixConn) error {
	identity, err := rootBrokerPeerBinding(socket, rootBrokerObservationSocket)
	if err != nil {
		return err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.binding == "" {
		reader.binding = identity.socket
	}
	if reader.binding != identity.socket {
		return rootoci.ErrUnauthorized
	}
	return nil
}

type rootBrokerPeerIdentity struct {
	process string
	socket  string
}

// Ordinary callers observe the kernel peer without opening or signaling root's executable.
func rootBrokerPeerBinding(socket *net.UnixConn, path string) (rootBrokerPeerIdentity, error) {
	if path != rootBrokerStartupSocket && path != rootBrokerObservationSocket && path != rootBrokerReconnectSocket && path != rootBrokerClientSocket && path != rootBrokerSourceSocket {
		return rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
	}
	peer, err := rootociwire.PeerCredential(socket)
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		return rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
	}
	start, parent, cgroup, err := rootociwire.KernelIdentity(peer.PID)
	if err != nil {
		return rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
	}
	for _, path := range []string{"/", "/run", "/run/terrascale-orchestrator"} {
		var stat unix.Stat_t
		if unix.Lstat(path, &stat) != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
			return rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
		}
	}
	var stat unix.Stat_t
	if unix.Lstat(path, &stat) != nil || stat.Uid != 0 ||
		stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Mode&0o7777 != 0o660 {
		return rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
	}
	process := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%d:%d:%d:%s", peer.PID, peer.UID, peer.GID, start, parent, cgroup))))
	return rootBrokerPeerIdentity{process: process, socket: fmt.Sprintf("%s:%d:%d", process, stat.Dev, stat.Ino)}, nil
}

func decodeRootBrokerResponse(wire []byte, operation rootBrokerOperation) (rootBrokerResponse, error) {
	var fields map[string]jsontext.Value
	if json.Unmarshal(wire, &fields) != nil || len(fields) != 1 {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	var response rootBrokerResponse
	if json.Unmarshal(wire, &response, json.RejectUnknownMembers(true)) != nil {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	if _, ok := fields["error"]; ok {
		switch response.Error {
		case "unauthorized":
			return rootBrokerResponse{}, rootoci.ErrUnauthorized
		case "stopped":
			return rootBrokerResponse{}, natscell.ErrEmbeddedServerStopped
		case "disabled":
			return rootBrokerResponse{}, natscell.ErrJetStreamDisabled
		default:
			return rootBrokerResponse{}, rootoci.ErrUnavailable
		}
	}
	if _, ok := fields[string(operation)]; !ok {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	valid := false
	switch operation {
	case rootBrokerCluster:
		valid = response.Cluster != nil
		if valid && !response.Cluster.Observation.Running {
			return response, natscell.ErrEmbeddedServerStopped
		}
	case rootBrokerMeta:
		valid = response.Meta != nil
	case rootBrokerMetrics:
		valid = response.Metrics != nil
	case rootBrokerStore:
		valid = response.Store != nil
	case rootBrokerStreams:
		valid = response.Streams != nil
	case rootBrokerAccount:
		valid = response.Account != nil
	}
	if !valid {
		return rootBrokerResponse{}, rootoci.ErrUnavailable
	}
	return response, nil
}
