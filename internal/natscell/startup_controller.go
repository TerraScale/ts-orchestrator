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
)

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
	if ctx == nil || ctx.Err() != nil || cfg.ClientRole != "controller" || len(cfg.OperatorForward) != 0 {
		return nil, errors.New("private broker startup requires the production controller role")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.URL == "" && cfg.Embedded != nil {
		cfg.URL = "nats://" + net.JoinHostPort(cfg.Embedded.Host, fmt.Sprint(cfg.Embedded.Port))
	}
	cfg.Embedded = nil
	return start(ctx, cfg, false, initial)
}

// ServeStartupController is called only by root after authenticating the exact
// MainPID and its original finite startup source; it never opens the public gate.
func (r *Runtime) ServeStartupController(ctx context.Context, admitted net.Conn, originalDeadline time.Time) error {
	if admitted == nil {
		return errors.New("private controller startup connection is missing")
	}
	defer admitted.Close()
	if ctx == nil || ctx.Err() != nil || r == nil || r.server == nil || r.brokerTLS == nil ||
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
	internal, err = r.server.InProcessConn()
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
