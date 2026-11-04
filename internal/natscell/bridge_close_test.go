package natscell

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBridgeFenceRevokesEveryNATSPathBeforeTLSShutdown(t *testing.T) {
	for _, action := range []string{"fence"} {
		t.Run(action, func(t *testing.T) {
			primaryListener, extraListener := bridgeTestListener(t), bridgeTestListener(t)
			extra, stalled, release := bridgeStalledTLS(t)
			primary, primaryPeer := net.Pipe()
			primaryInternal, primaryInternalPeer := net.Pipe()
			extraInternal, extraInternalPeer := net.Pipe()
			t.Cleanup(func() {
				_ = primaryPeer.Close()
				_ = primaryInternalPeer.Close()
				_ = extraInternalPeer.Close()
			})
			primaryNATS := &bridgeCloseSignal{Conn: primaryInternal, closed: make(chan struct{})}
			extraNATS := &bridgeCloseSignal{Conn: extraInternal, closed: make(chan struct{})}
			b := &Bridge{listener: primaryListener, open: true, deadline: time.Now().Add(time.Minute),
				listeners: map[net.Listener]struct{}{extraListener: {}}, pairs: map[*bridgePair]struct{}{
					{external: primary, internal: primaryNATS, listener: primaryListener}: {},
					{external: extra, internal: extraNATS, listener: extraListener}:       {},
				}}
			closed := make(chan struct{})
			t.Cleanup(func() {
				release()
				bridgeWait(t, closed, "fenced TLS shutdown did not finish")
				b.Close()
			})
			go func() {
				switch action {
				case "fence":
					b.Fence()
				case "claim":
					b.FenceClaim(2)
				case "close":
					b.Close()
				}
				close(closed)
			}()
			bridgeWait(t, stalled, "fenced TLS close did not stall")
			bridgeWait(t, primaryNATS.closed, "stalled TLS close left the primary NATS path usable")
			bridgeWait(t, extraNATS.closed, "stalled TLS close left the additional NATS path usable")
			status := make(chan BridgeStatus, 1)
			go func() { status <- b.Status() }()
			select {
			case got := <-status:
				if got.Open || got.ActiveSessions != 0 {
					t.Fatalf("fenced sessions remained admitted: %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("fenced TLS shutdown holds the shared bridge mutex")
			}
		})
	}
}

func bridgeTestListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

type bridgeCloseSignal struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *bridgeCloseSignal) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type bridgeTLSWriteSignal struct {
	net.Conn
	closing atomic.Bool
	stalled chan struct{}
}

func (c *bridgeTLSWriteSignal) Write(p []byte) (int, error) {
	if c.closing.Load() {
		select {
		case c.stalled <- struct{}{}:
		default:
		}
	}
	return c.Conn.Write(p)
}

func bridgeStalledTLS(t *testing.T) (*tls.Conn, <-chan struct{}, func()) {
	t.Helper()
	files := testBridgeTLS(t, t.TempDir())
	serverConfig, err := loadTLS(files, true)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig.SessionTicketsDisabled = true
	clientConfig, err := loadTLS(files, false)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.ServerName = testLeafServerName
	serverRaw, clientRaw := net.Pipe()
	release := func() { _ = serverRaw.Close(); _ = clientRaw.Close() }
	t.Cleanup(release)
	signal := &bridgeTLSWriteSignal{Conn: serverRaw, stalled: make(chan struct{}, 1)}
	serverTLS, clientTLS := tls.Server(signal, serverConfig), tls.Client(clientRaw, clientConfig)
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- serverTLS.HandshakeContext(t.Context()) }()
	if err := clientTLS.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatal(err)
	}
	// With no peer reader, net.Pipe blocks the TLS close_notify write.
	signal.closing.Store(true)
	return serverTLS, signal.stalled, release
}

func bridgeWait(t *testing.T, done <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal(failure)
	}
}
