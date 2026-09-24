package natscell

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A VM process can disappear while its TAP keeps TCP connections open. The
// host must detect that blackhole before its signed session becomes unusable.
func TestHostClientLeavesBlackholedPeerBeforeSessionReserve(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	primary, err := Start(ctx, Config{Cell: "lab", Instance: "primary", Replicas: 1, Lab: true,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "primary")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = primary.Close() })
	proxy := newBlackholeProxy(t, primary.ClientAddress().String())
	secondaryPort := freeClientPort(t)
	host, err := Start(ctx, Config{Cell: "lab", Instance: "host", Replicas: 1, Lab: true, ClientRole: "host",
		URL: fmt.Sprintf("nats://%s,nats://127.0.0.1:%d", proxy.listener.Addr(), secondaryPort)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	if got := host.Conn().ConnectedUrl(); got != "nats://"+proxy.listener.Addr().String() {
		t.Fatalf("host initially connected to %q, want proxy", got)
	}
	secondary, err := Start(ctx, Config{Cell: "lab", Instance: "secondary", Replicas: 1, Lab: true,
		Embedded: &Embedded{Host: "127.0.0.1", Port: secondaryPort, StoreDir: filepath.Join(t.TempDir(), "secondary")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondary.Close() })
	proxy.blocked.Store(true)
	started := time.Now()
	for host.Conn().ConnectedUrl() != secondary.URL() {
		if err := ctx.Err(); err != nil {
			t.Fatalf("host did not reconnect from blackholed peer before reserve: %v, url=%q", err,
				host.Conn().ConnectedUrl())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if elapsed := time.Since(started); elapsed >= 15*time.Second {
		t.Fatalf("host took %s to leave blackholed peer, exhausting session headroom", elapsed)
	}
}

func freeClientPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

type blackholeProxy struct {
	listener net.Listener
	blocked  atomic.Bool
	mu       sync.Mutex
	conns    []net.Conn
}

func newBlackholeProxy(t *testing.T, target string) *blackholeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &blackholeProxy{listener: listener}
	t.Cleanup(func() {
		_ = proxy.listener.Close()
		proxy.mu.Lock()
		defer proxy.mu.Unlock()
		for _, conn := range proxy.conns {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			proxy.mu.Lock()
			proxy.conns = append(proxy.conns, client, server)
			proxy.mu.Unlock()
			go proxy.forward(client, server)
			go proxy.forward(server, client)
		}
	}()
	return proxy
}

func (p *blackholeProxy) forward(source, destination net.Conn) {
	defer source.Close()
	defer destination.Close()
	var buffer [4096]byte
	for {
		count, err := source.Read(buffer[:])
		if err != nil {
			return
		}
		if !p.blocked.Load() {
			if _, err := destination.Write(buffer[:count]); err != nil {
				return
			}
		}
	}
}
