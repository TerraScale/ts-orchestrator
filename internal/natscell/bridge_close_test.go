package natscell

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
)

func TestAdditionalBridgeTLSCloseDoesNotDelayPrimaryFence(t *testing.T) {
	for _, expire := range []bool{false, true} {
		name := "explicit"
		if expire {
			name = "ticket-expiry"
		}
		t.Run(name, func(t *testing.T) {
			natsServer, account, claim := bridgeTestAccount(t)
			primaryListener := bridgeTestListener(t)
			extraListener := bridgeTestListener(t)
			primary, primaryPeer := net.Pipe()
			internal, internalPeer := net.Pipe()
			t.Cleanup(func() { _ = primaryPeer.Close(); _ = internalPeer.Close() })
			primaryClosed := &bridgeCloseSignal{Conn: primary, closed: make(chan struct{})}
			extra, stalled, release := bridgeStalledTLS(t)
			extraInternal, extraPeer := net.Pipe()
			t.Cleanup(func() { _ = extraPeer.Close() })
			b := &Bridge{server: natsServer, account: account, listener: primaryListener,
				listeners: map[net.Listener]struct{}{extraListener: {}}, pairs: map[*bridgePair]struct{}{
					{external: primaryClosed, internal: internal, listener: primaryListener}: {},
					{external: extra, internal: extraInternal, listener: extraListener}:      {},
				}}
			if err := b.OpenUntil(1, claim, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			closed := make(chan struct{})
			t.Cleanup(func() {
				release()
				b.Close()
				bridgeWait(t, closed, "additional listener close did not finish")
			})
			go func() {
				_ = (&bridgeListener{Listener: extraListener, bridge: b}).Close()
				close(closed)
			}()
			bridgeWait(t, stalled, "additional TLS close did not stall")
			status := make(chan BridgeStatus, 1)
			go func() { status <- b.Status() }()
			select {
			case got := <-status:
				if !got.Open || got.ActiveSessions != 1 {
					t.Fatalf("closing additional listener changed primary admission: %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("TLS shutdown holds the shared bridge mutex")
			}
			if !expire {
				go b.Fence()
			} else if err := b.OpenUntil(1, claim, time.Now().Add(20*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			bridgeWait(t, primaryClosed.closed, "stalled additional TLS close delayed primary fence")
			if got := b.Status(); got.Open || got.ActiveSessions != 0 {
				t.Fatalf("primary fence left admission open: %+v", got)
			}
			select {
			case <-closed:
				t.Fatal("additional TLS close unexpectedly finished before its peer read")
			default:
			}
		})
	}
}

func TestBridgeFenceRevokesEveryNATSPathBeforeTLSShutdown(t *testing.T) {
	for _, action := range []string{"fence", "claim", "close"} {
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

func TestBridgeCannotAcknowledgeRevocationBeforeNATSPathCloses(t *testing.T) {
	for _, action := range []string{"expiry", "fence", "claim", "close", "listener", "replacement"} {
		t.Run(action, func(t *testing.T) {
			natsServer, account, claim := bridgeTestAccount(t)
			primaryListener, extraListener := bridgeTestListener(t), bridgeTestListener(t)
			external, externalPeer := net.Pipe()
			internal, internalPeer := net.Pipe()
			pause := &bridgePausedClose{Conn: internal, entered: make(chan struct{}), resume: make(chan struct{})}
			var resumeOnce sync.Once
			resume := func() { resumeOnce.Do(func() { close(pause.resume) }) }
			t.Cleanup(func() {
				resume()
				_ = externalPeer.Close()
				_ = internalPeer.Close()
			})
			externalClosed := &bridgeCloseSignal{Conn: external, closed: make(chan struct{})}
			b := &Bridge{server: natsServer, account: account, listener: primaryListener,
				listeners: map[net.Listener]struct{}{extraListener: {}}, pairs: map[*bridgePair]struct{}{
					{external: externalClosed, internal: pause, listener: extraListener}: {},
				}}
			if err := b.OpenUntil(1, claim, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { resume(); b.Close() })
			initialDone := make(chan error, 1)
			if action == "expiry" {
				if err := b.OpenUntil(1, claim, time.Now().Add(20*time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			} else {
				go func() {
					var err error
					switch action {
					case "fence":
						b.Fence()
					case "claim":
						b.FenceClaim(2)
					case "close":
						b.Close()
					case "listener":
						err = (&bridgeListener{Listener: extraListener, bridge: b}).Close()
					case "replacement":
						err = b.OpenUntil(2, claim, time.Now().Add(time.Minute))
					}
					initialDone <- err
				}()
			}
			bridgeWait(t, pause.entered, "initial revocation did not reach NATS closure")
			acknowledged := make(chan struct{})
			go func() { b.FenceClaim(3); close(acknowledged) }()
			status := make(chan BridgeStatus, 1)
			go func() { status <- b.Status() }()
			select {
			case <-acknowledged:
				t.Fatal("replacement claim acknowledged closure while the old NATS path remained usable")
			case got := <-status:
				t.Fatalf("bridge published admission before the old NATS path closed: %+v", got)
			case <-time.After(100 * time.Millisecond):
			}
			resume()
			bridgeWait(t, acknowledged, "replacement claim did not finish after NATS closure")
			bridgeWait(t, externalClosed.closed, "initial revocation did not close the external path")
			if action != "expiry" {
				select {
				case err := <-initialDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("initial revocation did not finish")
				}
			}
		})
	}
}

func bridgeTestAccount(t *testing.T) (*server.Server, string, string) {
	t.Helper()
	keys := newTestRegionKeys(t)
	claim, err := jwt.NewAccountClaims(keys.cellID).Encode(keys.operator)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &server.MemAccResolver{}
	if err := resolver.Store(keys.cellID, claim); err != nil {
		t.Fatal(err)
	}
	natsServer, err := server.NewServer(&server.Options{DontListen: true, NoLog: true, NoSigs: true,
		TrustedKeys: []string{keys.operatorID}, AccountResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(natsServer.Shutdown)
	return natsServer, keys.cellID, claim
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

type bridgePausedClose struct {
	net.Conn
	entered, resume chan struct{}
	once            sync.Once
	err             error
}

func (c *bridgePausedClose) Close() error {
	c.once.Do(func() {
		close(c.entered)
		<-c.resume
		c.err = c.Conn.Close()
	})
	return c.err
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
