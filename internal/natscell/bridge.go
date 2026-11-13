package natscell

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

type bridgePair struct {
	external, internal net.Conn
	listener           net.Listener
}

func (p *bridgePair) close() {
	_ = p.internal.Close()
	_ = p.external.Close()
}

// Bridge is the only production client TCP listener. Its mTLS handshakes
// happen before NATS INFO; the NATS server itself has DontListen set. The gate
// starts closed and a fence closes every accepted socket, including live ones.
type Bridge struct {
	server    *server.Server
	listener  net.Listener
	listeners map[net.Listener]struct{}
	account   string
	mu        sync.Mutex
	open      bool
	closed    bool
	deadline  time.Time
	sequence  uint64
	floor     uint64
	jwt       string
	pairs     map[*bridgePair]struct{}
	timer     *time.Timer
}

func startBridge(s *server.Server, address string, tlsConfig *tls.Config, account string) (*Bridge, error) {
	if s == nil || tlsConfig == nil || account == "" {
		return nil, errors.New("production broker bridge is incomplete")
	}
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("listen for regional broker clients: %w", err)
	}
	b := &Bridge{server: s, listener: listener, account: account, pairs: make(map[*bridgePair]struct{}), listeners: make(map[net.Listener]struct{})}
	go b.accept(listener)
	return b, nil
}

// InProcessConn's net.Pipe close is nonblocking; revoke it before publishing
// detached sessions so a concurrent fence cannot acknowledge a usable path.
func (b *Bridge) fenceLocked() map[*bridgePair]struct{} {
	for pair := range b.pairs {
		_ = pair.internal.Close()
	}
	b.open = false
	b.sequence = 0
	b.jwt = ""
	b.deadline = time.Time{}
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	pairs := b.pairs
	b.pairs = make(map[*bridgePair]struct{})
	return pairs
}

func closeBridgeExternal(pairs map[*bridgePair]struct{}) {
	for pair := range pairs {
		_ = pair.external.Close()
	}
}

func (b *Bridge) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	pairs := b.fenceLocked()
	listeners := b.listeners
	b.listeners = make(map[net.Listener]struct{})
	b.mu.Unlock()
	_ = b.listener.Close()
	for listener := range listeners {
		_ = listener.Close()
	}
	closeBridgeExternal(pairs)
}

func (b *Bridge) accept(listener net.Listener) {
	defer func() {
		b.mu.Lock()
		delete(b.listeners, listener)
		b.mu.Unlock()
	}()
	for {
		external, err := listener.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		allowed := b.open && time.Now().Before(b.deadline) && !b.closed
		b.mu.Unlock()
		if !allowed {
			_ = external.Close()
			continue
		}
		go b.serve(external, listener)
	}
}

func (b *Bridge) serve(external net.Conn, listener net.Listener) {
	defer external.Close()
	if err := external.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	if err := external.(*tls.Conn).Handshake(); err != nil {
		return
	}
	if err := external.SetDeadline(time.Time{}); err != nil {
		return
	}
	internal, err := b.server.InProcessConnForAccount(b.account)
	if err != nil {
		return
	}
	pair := &bridgePair{external: external, internal: internal, listener: listener}
	b.mu.Lock()
	_, additional := b.listeners[listener]
	if b.closed || listener != b.listener && !additional || !b.open || !time.Now().Before(b.deadline) {
		b.mu.Unlock()
		pair.close()
		return
	}
	b.pairs[pair] = struct{}{}
	b.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(internal, external); done <- struct{}{} }()
	go func() { _, _ = io.Copy(external, internal); done <- struct{}{} }()
	<-done
	pair.close()
	<-done
	b.mu.Lock()
	delete(b.pairs, pair)
	b.mu.Unlock()
}
