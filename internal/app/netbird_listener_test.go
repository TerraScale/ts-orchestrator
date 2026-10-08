package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
)

type netbirdTestListener struct {
	net.Listener
	once   sync.Once
	closed func()
}

func (l *netbirdTestListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(l.closed)
	return err
}

func TestNetBirdMeshListenerRetriesRebindsAndCloses(t *testing.T) {
	n := netbirdRollout{fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}}, services: &specRegistry{}}
	var local atomic.Value
	local.Store(netip.MustParseAddr("10.200.1.2"))
	var first atomic.Bool
	first.Store(true)
	events := make(chan string, 16)
	listen := func(address netip.Addr) (net.Listener, error) {
		if first.Swap(false) {
			events <- "retry"
			return nil, errors.New("interface not ready")
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		events <- "listen " + address.String()
		return &netbirdTestListener{Listener: listener, closed: func() { events <- "close " + address.String() }}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.meshListenerLoop(ctx, func() netip.Addr { return local.Load().(netip.Addr) }, listen, 10*time.Millisecond)
	}()
	t.Cleanup(func() { cancel(); <-done })
	setPin := func(pin *cellspec.NetBird) {
		n.services.mu.Lock()
		n.services.current.NetBird = pin
		n.services.mu.Unlock()
	}
	want := func(expected string) {
		t.Helper()
		select {
		case event := <-events:
			if event != expected {
				t.Fatalf("listener event %q, want %q", event, expected)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("listener never emitted %q", expected)
		}
	}
	select {
	case event := <-events:
		t.Fatalf("disabled pin opened mesh listener: %s", event)
	case <-time.After(30 * time.Millisecond):
	}
	setPin(&cellspec.NetBird{})
	want("retry")
	want("listen 10.200.1.2")
	local.Store(netip.MustParseAddr("10.200.1.3"))
	want("close 10.200.1.2")
	want("listen 10.200.1.3")
	setPin(nil)
	want("close 10.200.1.3")
	setPin(&cellspec.NetBird{})
	want("listen 10.200.1.3")
	cancel()
	want("close 10.200.1.3")
}
