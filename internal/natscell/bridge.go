package natscell

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

var ErrBridgeClosed = errors.New("broker bridge is closed")

type bridgePair struct {
	external, internal net.Conn
	listener           net.Listener
}

type bridgeListener struct {
	net.Listener
	bridge *Bridge
}

func (l *bridgeListener) Close() error {
	l.bridge.mu.Lock()
	pairs := make(map[*bridgePair]struct{})
	for pair := range l.bridge.pairs {
		if pair.listener == l.Listener {
			_ = pair.internal.Close()
			delete(l.bridge.pairs, pair)
			pairs[pair] = struct{}{}
		}
	}
	delete(l.bridge.listeners, l.Listener)
	l.bridge.mu.Unlock()
	err := l.Listener.Close()
	closeBridgeExternal(pairs)
	return err
}

type BridgeStatus struct {
	Open           bool
	ClaimSequence  uint64
	JWTHash        string
	ActiveSessions int
	Deadline       time.Time
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

// Every additional listener shares the primary listener's mTLS and ticket
// fence, including closing its established sessions when that fence expires.
func (b *Bridge) listen(address string, config *tls.Config) (net.Listener, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrBridgeClosed
	}
	b.mu.Unlock()
	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("listen for regional broker clients at %s: %w", address, err)
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = listener.Close()
		return nil, ErrBridgeClosed
	}
	b.listeners[listener] = struct{}{}
	go b.accept(listener)
	b.mu.Unlock()
	return &bridgeListener{Listener: listener, bridge: b}, nil
}

func (b *Bridge) Addr() net.Addr { return b.listener.Addr() }

func (b *Bridge) Status() BridgeStatus {
	if b == nil {
		return BridgeStatus{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	status := BridgeStatus{Open: b.open && time.Now().Before(b.deadline), ClaimSequence: b.sequence,
		ActiveSessions: len(b.pairs), Deadline: b.deadline}
	if b.jwt != "" {
		digest := sha256.Sum256([]byte(b.jwt))
		status.JWTHash = hex.EncodeToString(digest[:])
	}
	return status
}

// OpenUntil requires local proof that NATS applied the exact durable account
// JWT. The caller must first verify an authority ticket and conservative
// monotonic deadline; this method does not mint or verify tickets.
func (b *Bridge) OpenUntil(sequence uint64, rawJWT string, deadline time.Time) error {
	if b == nil || sequence == 0 || rawJWT == "" || !time.Now().Before(deadline) {
		return errors.New("broker bridge ticket is invalid or expired")
	}
	if _, err := b.server.LookupAccount(b.account); err != nil {
		return fmt.Errorf("load broker account: %w", err)
	}
	accountz, err := b.server.Accountz(&server.AccountzOptions{Account: b.account})
	if err != nil || accountz.Account == nil || accountz.Account.Jwt != rawJWT {
		return errors.New("broker account JWT was not applied locally")
	}
	b.mu.Lock()
	if b.closed || sequence < b.floor {
		b.mu.Unlock()
		return errors.New("broker bridge is closed or claim sequence is stale")
	}
	var pairs map[*bridgePair]struct{}
	if b.open && (b.sequence != sequence || b.jwt != rawJWT) {
		pairs = b.fenceLocked()
	}
	b.sequence, b.jwt, b.deadline, b.open = sequence, rawJWT, deadline, true
	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(time.Until(deadline), func() {
		b.mu.Lock()
		var expired map[*bridgePair]struct{}
		if b.open && b.sequence == sequence && b.deadline.Equal(deadline) {
			expired = b.fenceLocked()
		}
		b.mu.Unlock()
		closeBridgeExternal(expired)
	})
	b.mu.Unlock()
	closeBridgeExternal(pairs)
	return nil
}

func (b *Bridge) Fence() {
	if b == nil {
		return
	}
	b.mu.Lock()
	pairs := b.fenceLocked()
	b.mu.Unlock()
	closeBridgeExternal(pairs)
}

// FenceClaim closes old sessions and prevents an earlier ticket from reopening
// the gate after a claim replacement, even if that ticket was already verified.
func (b *Bridge) FenceClaim(sequence uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.floor = max(b.floor, sequence)
	pairs := b.fenceLocked()
	b.mu.Unlock()
	closeBridgeExternal(pairs)
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
