package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
)

func openRootBrokerSourceClient(ctx context.Context, cfg Config, command string, query []byte) (*natscell.Runtime, error) {
	if ctx == nil || ctx.Err() != nil || cfg.NATS.Embedded == nil || os.Getppid() < 2 {
		return nil, rootoci.ErrUnauthorized
	}
	if _, _, err := rootBrokerSourceQuery(command, query); err != nil {
		return nil, err
	}
	preface, err := protocol.EncodeJSON(rootBrokerSourcePreface{Command: command, QuerySHA256: fmt.Sprintf("%x", sha256.Sum256(query))})
	if err != nil || len(preface) > rootBrokerSourceMaxPreface {
		return nil, rootoci.ErrUnauthorized
	}
	dialer := &rootBrokerSourceDialer{ctx: ctx, parent: os.Getppid(), preface: preface,
		address: net.JoinHostPort(cfg.NATS.Embedded.Host, fmt.Sprint(cfg.NATS.Embedded.Port))}
	cfg.NATS.ClientRole = "controller"
	probe, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	runtime, err := natscell.StartRootControllerClient(probe, cfg.NATS, dialer)
	dialer.mu.Lock()
	current := dialer.current
	valid := current != nil && dialer.verify(current.UnixConn) == nil
	dialer.mu.Unlock()
	if err != nil || probe.Err() != nil || !valid {
		if runtime != nil {
			_ = runtime.Close()
		}
		if current != nil {
			_ = current.Close()
		}
		if err != nil {
			return nil, err
		}
		return nil, rootoci.ErrUnauthorized
	}
	return runtime, nil
}

// Source children always cross the public reconnect gate, including their first dial.
type rootBrokerSourceDialer struct {
	ctx     context.Context
	parent  int
	address string
	preface []byte
	mu      sync.Mutex
	binding rootBrokerPeerIdentity
	current *rootBrokerSourceConnection
}

func (dialer *rootBrokerSourceDialer) Dial(network, address string) (net.Conn, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if network != "tcp" || address != dialer.address || dialer.ctx.Err() != nil || os.Getppid() != dialer.parent {
		return nil, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(dialer.ctx, 12*time.Second)
	defer cancel()
	connection, err := new(net.Dialer).DialContext(ctx, "unix", rootBrokerSourceSocket)
	if err != nil {
		return nil, err
	}
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, rootoci.ErrUnauthorized
	}
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	identity, err := rootBrokerPeerBinding(socket, rootBrokerSourceSocket)
	if err != nil || socket.SetDeadline(deadline) != nil || dialer.verify(socket) != nil ||
		rootociwire.WriteBoundedFrame(socket, dialer.preface, rootBrokerSourceMaxPreface) != nil {
		_ = socket.Close()
		return nil, rootoci.ErrUnauthorized
	}
	confirmed, err := rootBrokerPeerBinding(socket, rootBrokerSourceSocket)
	if err != nil || identity != confirmed || dialer.verify(socket) != nil || ctx.Err() != nil {
		_ = socket.Close()
		return nil, rootoci.ErrUnauthorized
	}
	// The original caller context, rather than this dial timeout, owns the stream.
	deadline, _ = dialer.ctx.Deadline()
	if socket.SetDeadline(deadline) != nil {
		_ = socket.Close()
		return nil, rootoci.ErrUnauthorized
	}
	dialer.binding = identity
	dialer.current = &rootBrokerSourceConnection{UnixConn: socket, stop: context.AfterFunc(dialer.ctx, func() { _ = socket.Close() })}
	return dialer.current, nil
}

func (dialer *rootBrokerSourceDialer) verify(socket *net.UnixConn) error {
	peer, err := rootociwire.PeerCredential(socket)
	if err != nil || peer.PID != dialer.parent || os.Getppid() != dialer.parent || dialer.ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	identity, err := rootBrokerPeerBinding(socket, rootBrokerSourceSocket)
	if err != nil || dialer.binding != (rootBrokerPeerIdentity{}) && identity != dialer.binding {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (*rootBrokerSourceDialer) SkipTLSHandshake() bool { return true }

type rootBrokerSourceConnection struct {
	*net.UnixConn
	stop func() bool
}

func (connection *rootBrokerSourceConnection) Close() error {
	connection.stop()
	return connection.UnixConn.Close()
}
