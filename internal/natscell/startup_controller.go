package natscell

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// Pin the claim actually authenticated by this broker, never a later read of
// the controller's writable credential path or a caller-supplied identity.
func (r *Runtime) captureStartupController() error {
	cid, err := r.conn.GetClientID()
	if err != nil {
		return err
	}
	view, err := r.server.Connz(&server.ConnzOptions{CID: cid, Username: true})
	if err != nil || view == nil || cid == 0 || len(view.Conns) != 1 || view.Conns[0].Cid != cid || view.Conns[0].Account != r.resolver.cell {
		return errors.New("private startup requires the original native controller account")
	}
	connection := view.Conns[0]
	claim, err := jwt.DecodeUserClaims(connection.JWT)
	if err != nil || claim.Subject != connection.AuthorizedUser || credentialAccount(claim) != r.resolver.cell {
		return errors.New("private startup requires the original native controller JWT")
	}
	r.controllerJWT = connection.JWT
	return nil
}

// StartControllerClient consumes an admitted private startup connection once.
// The same client reconnects through only the configured production gate.
func StartControllerClient(ctx context.Context, cfg Config, initial net.Conn) (_ *Runtime, err error) {
	if initial == nil {
		return nil, errors.New("controller startup requires its admitted private connection")
	}
	defer func() {
		if err != nil {
			_ = initial.Close()
		}
	}()
	if ctx == nil || ctx.Err() != nil || cfg.ClientRole != "controller" || cfg.Embedded == nil || len(cfg.OperatorForward) != 0 {
		return nil, errors.New("private broker startup requires the production controller role")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// The private socket is always this root broker, regardless of URL order.
	cfg.URL = "nats://" + net.JoinHostPort(cfg.Embedded.Host, fmt.Sprint(cfg.Embedded.Port))
	cfg.Embedded = nil
	return start(ctx, cfg, false, initial, nil)
}

// StartRootControllerClient keeps native JWT authentication in the ordinary
// client while its authenticated local transport delegates TLS to root.
func StartRootControllerClient(ctx context.Context, cfg Config, transport nats.CustomDialer) (*Runtime, error) {
	if ctx == nil || ctx.Err() != nil || transport == nil || cfg.ClientRole != "controller" || cfg.Embedded == nil || len(cfg.OperatorForward) != 0 {
		return nil, errors.New("root controller transport requires the production controller role")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.URL = "nats://" + net.JoinHostPort(cfg.Embedded.Host, fmt.Sprint(cfg.Embedded.Port))
	cfg.Embedded = nil
	return start(ctx, cfg, false, nil, transport)
}

// ServeStartupController is called only by root after authenticating the exact
// MainPID and its original finite startup source; it never opens the public gate.
func (r *Runtime) ServeStartupController(ctx context.Context, admitted net.Conn, originalDeadline time.Time) error {
	if admitted == nil {
		return errors.New("private controller startup connection is missing")
	}
	defer admitted.Close()
	if ctx == nil || ctx.Err() != nil || r == nil || r.server == nil || r.brokerTLS == nil || r.resolver == nil || r.controllerJWT == "" ||
		!r.server.Running() || !time.Now().Before(originalDeadline) {
		return errors.New("private controller startup authority is unavailable")
	}
	ctx, cancel := context.WithDeadline(ctx, originalDeadline)
	defer cancel()
	var mu sync.Mutex
	var internal net.Conn
	closePair := func() {
		mu.Lock()
		if internal != nil {
			_ = internal.Close()
		}
		mu.Unlock()
		_ = admitted.Close()
	}
	stop := context.AfterFunc(ctx, closePair)
	defer stop()
	defer closePair()
	secured := tls.Server(admitted, r.brokerTLS.ServerConfig())
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	mu.Lock()
	if ctx.Err() != nil {
		mu.Unlock()
		return ctx.Err()
	}
	var err error
	internal, err = r.server.InProcessConnForJWT(r.resolver.cell, r.controllerJWT)
	mu.Unlock()
	if err != nil {
		return err
	}
	done := make(chan error, 2)
	go func() { _, err := io.Copy(internal, secured); done <- err }()
	go func() { _, err := io.Copy(secured, internal); done <- err }()
	first := <-done
	closePair()
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !r.server.Running() {
		return ErrEmbeddedServerStopped
	}
	return first
}
