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

type bridgePair struct{ external, internal net.Conn }

type BridgeStatus struct {
	Open           bool
	ClaimSequence  uint64
	JWTHash        string
	ActiveSessions int
	Deadline       time.Time
}

func (p *bridgePair) close() {
	_ = p.external.Close()
	_ = p.internal.Close()
}

// Bridge is the only production client TCP listener. Its mTLS handshakes
// happen before NATS INFO; the NATS server itself has DontListen set. The gate
// starts closed and a fence closes every accepted socket, including live ones.
type Bridge struct {
	server   *server.Server
	listener net.Listener
	account  string
	mu       sync.Mutex
	open     bool
	closed   bool
	deadline time.Time
	sequence uint64
	floor    uint64
	jwt      string
	pairs    map[*bridgePair]struct{}
	timer    *time.Timer
}

func startBridge(s *server.Server, address string, tlsConfig *tls.Config, account string) (*Bridge, error) {
	if s == nil || tlsConfig == nil || account == "" {
		return nil, errors.New("production broker bridge is incomplete")
	}
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("listen for regional broker clients: %w", err)
	}
	b := &Bridge{server: s, listener: listener, account: account, pairs: make(map[*bridgePair]struct{})}
	go b.accept()
	return b, nil
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
	defer b.mu.Unlock()
	if b.closed || sequence < b.floor {
		return errors.New("broker bridge is closed or claim sequence is stale")
	}
	if b.open && (b.sequence != sequence || b.jwt != rawJWT) {
		b.fenceLocked()
	}
	b.sequence, b.jwt, b.deadline, b.open = sequence, rawJWT, deadline, true
	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(time.Until(deadline), func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.open && b.sequence == sequence && b.deadline.Equal(deadline) {
			b.fenceLocked()
		}
	})
	return nil
}

func (b *Bridge) Fence() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.fenceLocked()
	b.mu.Unlock()
}

// FenceClaim closes old sessions and prevents an earlier ticket from reopening
// the gate after a claim replacement, even if that ticket was already verified.
func (b *Bridge) FenceClaim(sequence uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.floor = max(b.floor, sequence)
	b.fenceLocked()
	b.mu.Unlock()
}

func (b *Bridge) fenceLocked() {
	b.open = false
	b.sequence = 0
	b.jwt = ""
	b.deadline = time.Time{}
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	for p := range b.pairs {
		p.close()
	}
}

func (b *Bridge) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.fenceLocked()
		_ = b.listener.Close()
	}
	b.mu.Unlock()
}

func (b *Bridge) accept() {
	for {
		external, err := b.listener.Accept()
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
		go b.serve(external)
	}
}

func (b *Bridge) serve(external net.Conn) {
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
	internal, err := b.server.InProcessConn()
	if err != nil {
		return
	}
	pair := &bridgePair{external: external, internal: internal}
	b.mu.Lock()
	if b.closed || !b.open || !time.Now().Before(b.deadline) {
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
