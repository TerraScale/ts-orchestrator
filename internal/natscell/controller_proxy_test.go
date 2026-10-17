package natscell

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControllerProxyGateTransitions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	proxy, err := NewControllerProxy(root)
	if err != nil {
		t.Fatal(err)
	}
	initialContext, stopInitial := context.WithCancel(ctx)
	initial, initialDone := controllerProxyUnix(t, func(conn net.Conn) error {
		return proxy.ServeInitial(initialContext, conn, time.Now().Add(15*time.Second))
	})
	reader, nonce := controllerProxyInfo(t, initial)
	writeStartupConnect(t, initial, region.cfg.CredentialsFile, nonce)
	if line, err := reader.ReadString('\n'); err != nil || line != "PONG\r\n" {
		t.Fatalf("ordinary private startup: %q %v", line, err)
	}
	if status := root.Bridge().Status(); status.Open || status.ActiveSessions != 0 {
		t.Fatalf("private startup changed the public gate: %+v", status)
	}
	stopInitial()
	if err := controllerProxyDone(t, ctx, initialDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("private source cancellation: %v", err)
	}
	if _, err := initial.Read(make([]byte, 1)); err == nil {
		t.Fatal("ordinary startup stream survived its original source")
	}
	closed, closedDone := controllerProxyUnix(t, func(conn net.Conn) error {
		return proxy.ServeReconnect(ctx, conn)
	})
	if count, err := closed.Read(make([]byte, 1)); count != 0 || err == nil {
		t.Fatal("closed public gate admitted an ordinary reconnect")
	}
	if err := controllerProxyDone(t, ctx, closedDone); err == nil {
		t.Fatal("reconnect bypassed the closed public TCP gate")
	}
	claim := root.InitialCellJWT()
	if err := root.ApplyCellClaim(ctx, 1, claim); err != nil {
		t.Fatal(err)
	}
	// This is the real native gate; APP separately verifies production tickets.
	if err := root.Bridge().OpenUntil(1, claim, time.Now().Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	reconnected, reconnectDone := controllerProxyUnix(t, func(conn net.Conn) error {
		return proxy.ServeReconnect(ctx, conn)
	})
	reader, nonce = controllerProxyInfo(t, reconnected)
	writeStartupConnect(t, reconnected, region.cfg.CredentialsFile, nonce)
	if line, err := reader.ReadString('\n'); err != nil || line != "PONG\r\n" {
		t.Fatalf("ordinary reconnect through the public gate: %q %v", line, err)
	}
	if root.Bridge().Status().ActiveSessions != 1 {
		t.Fatal("ordinary reconnect did not reach the existing public bridge")
	}
	root.Bridge().Fence()
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("fenced public gate retained the ordinary reconnect")
	}
	controllerProxyDone(t, ctx, reconnectDone)
	reused, reusedDone := controllerProxyUnix(t, func(conn net.Conn) error {
		return proxy.ServeInitial(ctx, conn, time.Now().Add(5*time.Second))
	})
	if count, err := reused.Read(make([]byte, 1)); count != 0 || err == nil {
		t.Fatal("the original private startup allowance was reused")
	}
	if err := controllerProxyDone(t, ctx, reusedDone); err == nil {
		t.Fatal("a second initial accept renewed private startup")
	}
}

func TestControllerProxyNativeIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	clientProxy, err := NewControllerProxy(root)
	if err != nil {
		t.Fatal(err)
	}
	clientStream, clientDone := controllerProxyUnix(t, func(conn net.Conn) error {
		return clientProxy.ServeInitial(ctx, conn, time.Now().Add(10*time.Second))
	})
	clientConfig := region.cfg
	clientConfig.ClientRole = "controller"
	// The ordinary start must never open this private TLS path.
	clientConfig.TLS.KeyFile = filepath.Join(t.TempDir(), "root-only-key-does-not-exist.pem")
	client, err := StartRootControllerClient(ctx, clientConfig, &controllerProxySingleDial{connection: clientStream})
	if err != nil {
		t.Fatalf("native ordinary client through root TLS: %v", err)
	}
	if err := client.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	client.Close()
	controllerProxyDone(t, ctx, clientDone)

	proxy, err := NewControllerProxy(root)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, done := controllerProxyUnix(t, func(conn net.Conn) error {
		return proxy.ServeInitial(ctx, conn, time.Now().Add(10*time.Second))
	})
	reader, nonce := controllerProxyInfo(t, ordinary)
	writeStartupConnect(t, ordinary, region.cfg.CredentialsFile, nonce)
	if line, err := reader.ReadString('\n'); err != nil || line != "PONG\r\n" {
		t.Fatalf("original native identity: %q %v", line, err)
	}
	writeStartupConnect(t, ordinary, broaderStartupControllerCredentials(t, region), nonce)
	line, err := reader.ReadString('\n')
	if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
		t.Fatal("the pinned JWT change was not rejected before the protocol deadline")
	}
	if err == nil && !strings.HasPrefix(line, "-ERR ") {
		t.Fatalf("plaintext ordinary stream changed the private native JWT: %q %v", line, err)
	}
	_ = ordinary.Close()
	controllerProxyDone(t, ctx, done)
}

func TestControllerProxyFailedInitialConsumed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, root := startupControllerBroker(t, ctx)
	proxy, err := NewControllerProxy(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, deadline := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(10 * time.Second)} {
		ordinary, done := controllerProxyUnix(t, func(conn net.Conn) error {
			return proxy.ServeInitial(ctx, conn, deadline)
		})
		if count, err := ordinary.Read(make([]byte, 1)); count != 0 || err == nil {
			t.Fatal("a failed initial attempt renewed private startup")
		}
		if err := controllerProxyDone(t, ctx, done); err == nil {
			t.Fatal("expired or consumed private startup was accepted")
		}
	}
}

func TestControllerProxyRetainedTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	proxy, err := NewControllerProxy(root)
	if err != nil {
		t.Fatal(err)
	}
	read, err := readTLSFiles(region.cfg.Embedded.TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(read.key)
	replacement, err := parseTLSMaterial(read)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the real server's identical certificate while destroying the
	// objects from which the proxy took its client snapshot.
	root.brokerTLS.mu.Lock()
	original := root.brokerTLS.current
	root.brokerTLS.current = replacement
	root.brokerTLS.mu.Unlock()
	original.certificate.Certificate[0][0] ^= 0xff
	original.certificate.PrivateKey.(*ecdsa.PrivateKey).D.SetInt64(0)
	*original.roots = *x509.NewCertPool()
	ordinary, done := controllerProxyUnix(t, func(conn net.Conn) error {
		return proxy.ServeInitial(ctx, conn, time.Now().Add(10*time.Second))
	})
	reader, nonce := controllerProxyInfo(t, ordinary)
	writeStartupConnect(t, ordinary, region.cfg.CredentialsFile, nonce)
	if line, err := reader.ReadString('\n'); err != nil || line != "PONG\r\n" {
		t.Fatalf("proxy lost its retained TLS material: %q %v", line, err)
	}
	_ = ordinary.Close()
	controllerProxyDone(t, ctx, done)
}

// These are actual Unix streams carrying plaintext NATS. Only the root proxy
// has TLS material; this fixture does not claim APP's installed-process custody.
func controllerProxyUnix(t *testing.T, serve func(net.Conn) error) (net.Conn, <-chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nats.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ordinary, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ordinary.Close() })
	root, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	t.Cleanup(func() { _ = root.Close() })
	if err := ordinary.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serve(root) }()
	return ordinary, done
}

func controllerProxyInfo(t *testing.T, ordinary net.Conn) (*bufio.Reader, string) {
	t.Helper()
	reader := bufio.NewReader(ordinary)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("native INFO over ordinary Unix stream: %q %v", line, err)
	}
	var info struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "INFO "))), &info); err != nil || info.Nonce == "" {
		t.Fatalf("native nonce: %v", err)
	}
	return reader, info.Nonce
}

func controllerProxyDone(t *testing.T, ctx context.Context, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		t.Fatal("root proxy did not join its TLS session")
		return ctx.Err()
	}
}

// The real Unix stream is already paired with the genuine root proxy above.
type controllerProxySingleDial struct{ connection net.Conn }

func (dialer *controllerProxySingleDial) Dial(string, string) (net.Conn, error) {
	if dialer.connection == nil {
		return nil, errors.New("the test startup connection was consumed")
	}
	connection := dialer.connection
	dialer.connection = nil
	return connection, nil
}

func (*controllerProxySingleDial) SkipTLSHandshake() bool { return true }
