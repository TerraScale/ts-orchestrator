// Package natsconnect opens bounded, authenticated sessions from captured identity material.
package natsconnect

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/nats-io/nats.go"
	"net"
	"time"
)

// Config contains already captured and verified credentials. Connect never
// reads credential files, retries, or enables a reconnect buffer.
type Config struct {
	URL        string
	TLS        *tls.Config
	PublicNKey string
	Sign       nats.SignatureHandler
	Timeout    time.Duration
}

type pendingSocket struct {
	connection net.Conn
	stop       func() bool
	done       chan struct{}
}

// NATS calls Dial serially during initial connection; reconnect is disabled.
type contextDialer struct {
	ctx     context.Context
	dialer  net.Dialer
	sockets []*pendingSocket
}

func (d *contextDialer) Dial(network, address string) (net.Conn, error) {
	connection, err := d.dialer.DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	socket := &pendingSocket{connection: connection, done: make(chan struct{})}
	socket.stop = context.AfterFunc(d.ctx, func() { connection.Close(); close(socket.done) })
	d.sockets = append(d.sockets, socket)
	return connection, nil
}
func (d *contextDialer) finish(keep bool) bool {
	for _, socket := range d.sockets {
		if socket.stop() {
			close(socket.done)
		} else {
			<-socket.done
			keep = false
		}
	}
	if d.ctx.Err() != nil {
		keep = false
	}
	if !keep {
		for _, socket := range d.sockets {
			socket.connection.Close()
		}
	}
	return keep
}

// Connect transfers socket ownership only after the complete authenticated
// INFO/TLS/PONG setup; cancellation closes and joins every pending socket.
func Connect(ctx context.Context, config Config, network net.Dialer) (*nats.Conn, error) {
	if ctx == nil || config.TLS == nil || config.Sign == nil || config.PublicNKey == "" || config.Timeout <= 0 || config.Timeout > 15*time.Second {
		return nil, errors.New("bounded NATS connection identity and timeout are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	dialer := &contextDialer{ctx: bounded, dialer: network}
	transferred := false
	defer func() {
		if !transferred {
			dialer.finish(false)
		}
	}()
	settings := nats.GetDefaultOptions()
	settings.Url = config.URL
	for _, option := range []nats.Option{nats.Secure(config.TLS), nats.Nkey(config.PublicNKey, config.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1), nats.RetryOnFailedConnect(false), nats.SkipHostLookup(), nats.SetCustomDialer(dialer)} {
		if err := option(&settings); err != nil {
			return nil, err
		}
	}
	deadline, _ := bounded.Deadline()
	settings.Timeout = time.Until(deadline)
	if settings.Timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	connection, err := settings.Connect()
	if err != nil {
		return nil, connectionFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		connection.Close()
		return nil, err
	}
	state, err := connection.TLSConnectionState()
	if err != nil || !connection.AuthRequired() || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		connection.Close()
		return nil, errors.New("global worker connection did not establish authenticated verified TLS 1.3")
	}
	if !dialer.finish(true) {
		connection.Close()
		if err := bounded.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}
	transferred = true
	return connection, nil
}

// A socket deadline may fire before the context timer goroutine records Err.
// Normalize against the absolute deadline too, retaining cancellation precedence.
func connectionFailure(ctx context.Context, cause error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return cause
}
