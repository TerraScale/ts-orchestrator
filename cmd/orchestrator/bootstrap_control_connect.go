package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
)

// Each lazy connection belongs to its requesting operation, not construction.
func newBootstrapStoreConnector(stores map[string]bootstrap.ControlNATSStore, connections map[string]*nats.Conn, owner *bootstrapControlProvider) func(context.Context, string) (*nats.Conn, error) {
	gate := make(chan struct{}, 1)
	return func(ctx context.Context, name string) (*nats.Conn, error) {
		if ctx == nil {
			return nil, errors.New("control: connection context required")
		}
		select {
		case gate <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() { <-gate }()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if existing := connections[name]; existing != nil {
			return existing, nil
		}
		store, ok := stores[name]
		if !ok {
			return nil, errors.New("control: unknown NATS store")
		}
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			connection, err := dialBootstrapStore(ctx, store)
			if err == nil {
				state, tlsErr := connection.TLSConnectionState()
				if tlsErr != nil || len(state.VerifiedChains) == 0 {
					connection.Close()
					return nil, errors.New("control: verified TLS required")
				}
				connections[name] = connection
				owner.connections = append(owner.connections, connection)
				return connection, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var networkError net.Error
			if !errors.As(err, &networkError) && !errors.Is(err, nats.ErrNoServers) && !errors.Is(err, io.EOF) {
				return nil, err
			}
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
}

// Closing in-progress sockets also cancels TLS and NATS protocol handshakes.
func dialBootstrapStore(ctx context.Context, store bootstrap.ControlNATSStore) (*nats.Conn, error) {
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &bootstrapContextDialer{ctx: attempt}
	stop := context.AfterFunc(attempt, dialer.close)
	options := append([]nats.Option(nil), store.Options...)
	options = append(options, nats.Timeout(5*time.Second), nats.NoReconnect(), nats.SetCustomDialer(dialer))
	connection, err := nats.Connect(store.URL, options...)
	if !stop() || attempt.Err() != nil {
		dialer.close()
		if connection != nil {
			connection.Close()
		}
		return nil, attempt.Err()
	}
	if err != nil {
		dialer.close()
	}
	return connection, err
}

type bootstrapContextDialer struct {
	ctx     context.Context
	mu      sync.Mutex
	closed  bool
	sockets []net.Conn
}

func (d *bootstrapContextDialer) Dial(network, address string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		connection.Close()
		return nil, context.Canceled
	}
	d.sockets = append(d.sockets, connection)
	return connection, nil
}
func (d *bootstrapContextDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, socket := range d.sockets {
		socket.Close()
	}
}
