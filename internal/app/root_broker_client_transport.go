package app

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// The ordinary client signs its native NATS nonce over root-authenticated Unix;
// TLS credentials and the production TCP gate stay in the root process.
type rootControllerDialer struct {
	ctx         context.Context
	address     string
	rootBinding string
	mu          sync.Mutex
	initial     net.Conn
}

func (dialer *rootControllerDialer) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" || address != dialer.address || dialer.ctx.Err() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	dialer.mu.Lock()
	initial := dialer.initial
	dialer.initial = nil
	dialer.mu.Unlock()
	if initial != nil {
		return initial, nil
	}
	ctx, cancel := context.WithTimeout(dialer.ctx, 12*time.Second)
	defer cancel()
	connection, err := new(net.Dialer).DialContext(ctx, "unix", rootBrokerClientSocket)
	if err != nil {
		return nil, err
	}
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, rootoci.ErrUnauthorized
	}
	peer, err := nativerootoci.PeerCredential(socket)
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		_ = socket.Close()
		return nil, rootoci.ErrUnauthorized
	}
	witness, err := rootoci.CaptureProcess(peer.PID)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	defer witness.Close()
	if _, err := rootBrokerPeerBinding(socket, witness, rootBrokerClientSocket); err != nil || witness.Binding() != dialer.rootBinding || ctx.Err() != nil {
		_ = socket.Close()
		return nil, rootoci.ErrUnauthorized
	}
	return socket, nil
}

func (*rootControllerDialer) SkipTLSHandshake() bool { return true }

func (broker *rootBrokerRuntime) serveClientTransport(parent context.Context, conn *net.UnixConn) {
	probe, stopProbe := context.WithTimeout(parent, 30*time.Second)
	peer, err := nativerootoci.PeerCredential(conn)
	if err != nil {
		stopProbe()
		return
	}
	lease, err := broker.authority.authorizeRuntime(probe, peer)
	stopProbe()
	if err != nil {
		return
	}
	broker.authority.mu.Lock()
	process := broker.authority.main
	if process == nil || process.witness.Peer() != peer || process.brokerStartup == nil || process.brokerStartup.transport == nil {
		broker.authority.mu.Unlock()
		return
	}
	transport := process.brokerStartup.transport
	broker.authority.mu.Unlock()
	ctx, cancel := context.WithDeadline(parent, lease.Deadline)
	defer cancel()
	stopLease := context.AfterFunc(lease.Context, cancel)
	defer stopLease()
	guard := func() error {
		if ctx.Err() != nil || lease.Context.Err() != nil || process.witness.Verify() != nil {
			return rootoci.ErrUnauthorized
		}
		current, err := broker.authority.authorizeRuntime(ctx, peer)
		if err != nil || current.Context != lease.Context || current.Binding != lease.Binding || current.Deadline != lease.Deadline {
			return rootoci.ErrUnauthorized
		}
		if err := broker.guard(ctx); err != nil {
			return err
		}
		if ctx.Err() != nil || lease.Context.Err() != nil || process.witness.Verify() != nil {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if guard() != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if guard() != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	_ = transport.ServeReconnect(ctx, conn)
}
