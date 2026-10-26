package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// TestEdgeIssuesCertificateAndProxies runs an in-process Pebble ACME server
// that validates HTTP-01 against the edge's :80 listener, then proxies HTTP,
// SSE, websocket and gRPC through :443 to loopback backends.
func TestEdgeIssuesCertificateAndProxies(t *testing.T) {
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	httpLn := listen(t)
	tlsLn := listen(t)
	// A dual-stack listener, like the edge's ":5432": IPv4 clients arrive IPv4-mapped.
	pgLn, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pgLn.Close() })
	pgBackend, pgGot, pgHeaders := echoBackend(t)
	wireLn, wireBackend := listen(t), listen(t)
	wireAccepted := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := wireBackend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				first := make([]byte, 64)
				n, err := conn.Read(first)
				if err != nil {
					return
				} // TCP readiness probes close without application data.
				wireAccepted <- struct{}{}
				conn.Write(first[:n])
				io.Copy(conn, conn)
			}()
		}
	}()

	logger := log.New(io.Discard, "", 0)
	store := db.NewMemoryStore()
	authority := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {}})
	validator := va.New(logger, httpLn.Addr().(*net.TCPAddr).Port, 0, false, startDNS(t), store)
	frontend := wfe.New(logger, store, validator, authority, []string{"pebble.letsencrypt.org"}, false, false, 3, 5)
	acmeServer := httptest.NewTLSServer(finalizeLocation(frontend.Handler()))
	t.Cleanup(acmeServer.Close)

	// Like netbird-server, one cleartext backend serves gRPC over h2c beside
	// HTTP/1.1, SSE and websockets.
	app := httptest.NewUnstartedServer(appBackend())
	app.Config.Protocols = new(http.Protocols)
	app.Config.Protocols.SetHTTP1(true)
	app.Config.Protocols.SetUnencryptedHTTP2(true)
	app.Start()
	t.Cleanup(app.Close)

	stateDir := t.TempDir()
	e := newEdge(stateDir, &acme.Client{DirectoryURL: acmeServer.URL + wfe.DirectoryPath, HTTPClient: acmeServer.Client()})
	e.SetRoutes(map[string]int{
		"App.Edge.Test": app.Listener.Addr().(*net.TCPAddr).Port,
	}, map[string]int{"PG.Edge.Test": pgBackend})
	notReady := listen(t)
	unavailablePort := notReady.Addr().(*net.TCPAddr).Port
	notReady.Close()
	e.SetWireRoutes(map[string]int{"Wire.Edge.Test": unavailablePort})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	served := make(chan error, 1)
	// Exercise the production listener-opening path, including a real bind
	// collision with the pre-existing plaintext wire listener.
	wireConflict := make(chan struct{}, 1)
	wireBound := make(chan struct{})
	pgConflict, pgBound := make(chan struct{}, 1), make(chan struct{})
	firewallClosed := make(chan struct{}, 8)
	var firewallOpen atomic.Bool
	e.wireFirewall = func(_ context.Context, open bool) error {
		if open {
			select {
			case <-wireBound:
			default:
				return fmt.Errorf("wire firewall opened before socket bind")
			}
		}
		firewallOpen.Store(open)
		if !open {
			select {
			case firewallClosed <- struct{}{}:
			default:
			}
		}
		return nil
	}
	e.listen = func(network, address string) (net.Listener, error) {
		switch address {
		case ":80":
			return httpLn, nil
		case ":443":
			return tlsLn, nil
		case ":5432":
			ln, err := net.Listen(network, pgLn.Addr().String())
			if err != nil {
				select {
				case pgConflict <- struct{}{}:
				default:
				}
			} else {
				close(pgBound)
			}
			return ln, err
		case ":7464":
			ln, err := net.Listen(network, wireLn.Addr().String())
			if err != nil {
				select {
				case wireConflict <- struct{}{}:
				default:
				}
			} else {
				close(wireBound)
			}
			return ln, err
		default:
			return nil, fmt.Errorf("unexpected production listener %s", address)
		}
	}
	go func() { served <- e.Run(ctx) }()

	roots := x509.NewCertPool()
	roots.AddCert(authority.GetRootCert(0).Cert)
	dialTLS := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", tlsLn.Addr().String())
	}

	t.Run("redirect", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", httpLn.Addr().String())
			}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := client.Get("http://app.edge.test/path?q=1")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://app.edge.test/path?q=1" {
			t.Fatalf("redirect = %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		resp, err = client.Get("http://other.edge.test/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unrouted host on :80 = %d, want 404", resp.StatusCode)
		}
	})

	client := &http.Client{Transport: &http.Transport{
		DialContext:       dialTLS,
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2: true,
	}}

	t.Run("http", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://app.edge.test/hello", nil)
		req.Header.Set("X-Real-IP", "203.0.113.9")
		req.Header.Set("CF-Connecting-IP", "203.0.113.9")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got, want := string(body), "host=app.edge.test proto=https path=/hello spoofed="; got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
		for name, want := range map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Content-Security-Policy":   "frame-ancestors 'none'",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
			"Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		} {
			if got := resp.Header.Get(name); got != want {
				t.Fatalf("%s = %q, want %q", name, got, want)
			}
		}
		if _, err := os.Stat(filepath.Join(stateDir, "edge-certs", "app.edge.test")); err != nil {
			t.Fatalf("certificate not cached: %v", err)
		}
	})

	t.Run("body limit", func(t *testing.T) {
		resp, err := client.Post("https://app.edge.test/upload", "application/octet-stream", io.LimitReader(zeros{}, 33<<20))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("a 33 MiB body reached the backend")
		}
	})

	t.Run("sse", func(t *testing.T) {
		resp, err := client.Get("https://app.edge.test/events")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		// The backend holds the stream open, so this line arrives only if the
		// proxy flushes each event.
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		if err != nil || line != "data: hello\n" {
			t.Fatalf("event = %q, %v", line, err)
		}
	})

	t.Run("websocket", func(t *testing.T) {
		conn, err := tls.Dial("tcp", tlsLn.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "app.edge.test", NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		config, err := websocket.NewConfig("wss://app.edge.test/ws", "https://app.edge.test")
		if err != nil {
			t.Fatal(err)
		}
		ws, err := websocket.NewClient(config, conn)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()
		if err := websocket.Message.Send(ws, "ping"); err != nil {
			t.Fatal(err)
		}
		var reply string
		if err := websocket.Message.Receive(ws, &reply); err != nil || reply != "echo ping" {
			t.Fatalf("reply = %q, %v", reply, err)
		}
	})

	t.Run("grpc", func(t *testing.T) {
		conn, err := grpc.NewClient("passthrough:///app.edge.test",
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) { return dialTLS(ctx, "tcp", addr) }),
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "app.edge.test"})))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			t.Fatalf("health = %v, %v", resp, err)
		}
	})

	t.Run("unknown host", func(t *testing.T) {
		conn, err := tls.Dial("tcp", tlsLn.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "other.edge.test"})
		if err == nil {
			conn.Close()
			t.Fatal("handshake for a hostname without a route succeeded")
		}
	})

	dialPG := func(t *testing.T, host string, packets ...[]byte) net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(pgLn.Addr().(*net.TCPAddr).Port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		for _, packet := range packets {
			if _, err := conn.Write(packet); err != nil {
				t.Fatal(err)
			}
		}
		return conn
	}
	pg := func(t *testing.T, packets ...[]byte) net.Conn { return dialPG(t, "127.0.0.1", packets...) }
	// wantHeader is the PROXY v2 header naming conn's client and the edge address it dialed.
	wantHeader := func(conn net.Conn) []byte {
		src, dst := conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr)
		header := []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\x7f\x00\x00\x01\x7f\x00\x00\x01")
		if src.IP.To4() == nil {
			header = append([]byte("\r\n\r\n\x00\r\nQUIT\n\x21\x21\x00\x24"), append(net.IPv6loopback, net.IPv6loopback...)...)
		}
		return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(header, uint16(src.Port)), uint16(dst.Port))
	}
	roundTrip := func(t *testing.T, conn net.Conn) {
		t.Helper()
		packet := append(binary.BigEndian.AppendUint32([]byte{'Q'}, 10), []byte("hello\x00")...)
		if _, err := conn.Write(packet); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(packet))
		if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, packet) || !bytes.Equal(<-pgGot, packet) {
			t.Fatalf("echo = %q, %v", reply, err)
		}
		if got, want := <-pgHeaders, wantHeader(conn); !bytes.Equal(got, want) {
			t.Fatalf("PROXY header = %x, want %x", got, want)
		}
	}
	startup := func(code uint32) []byte { return binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, code) }

	t.Run("postgres collision preserves HTTPS and recovers", func(t *testing.T) {
		select {
		case <-pgConflict:
		case <-time.After(10 * time.Second):
			t.Fatal("Postgres conflict not exercised")
		}
		// All earlier HTTP/HTTPS/gRPC subtests ran with Postgres still occupied.
		pgLn.Close()
		select {
		case <-pgBound:
		case <-time.After(15 * time.Second):
			t.Fatal("Postgres did not recover")
		}
	})

	t.Run("wire collision preserves full edge and recovers", func(t *testing.T) {
		if firewallOpen.Load() {
			t.Fatal("wire firewall opened while backend unavailable")
		}
		if e.wireReady(ctx) {
			t.Fatal("unavailable private backend reported ready")
		}
		select {
		case <-wireConflict:
			t.Fatal("public wire bind attempted before private backend was ready")
		default:
		}
		e.SetWireRoutes(map[string]int{"Wire.Edge.Test": wireBackend.Addr().(*net.TCPAddr).Port})
		select {
		case <-wireConflict:
		case <-time.After(10 * time.Second):
			t.Fatal("wire bind conflict was not exercised")
		}
		// Fresh HTTP, HTTPS and Postgres requests must all work after the
		// real :7464 bind failure, while the conflicting socket stays open.
		plain, err := net.DialTimeout("tcp", httpLn.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("HTTP lost during wire conflict: %v", err)
		}
		plain.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(plain, "GET / HTTP/1.1\r\nHost: app.edge.test\r\nConnection: close\r\n\r\n")
		redirected, err := http.ReadResponse(bufio.NewReader(plain), nil)
		if err != nil || redirected.StatusCode != http.StatusFound {
			t.Fatalf("HTTP during wire conflict: %v %v", redirected, err)
		}
		redirected.Body.Close()
		plain.Close()
		https, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", tlsLn.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "app.edge.test"})
		if err != nil {
			t.Fatalf("HTTPS lost during wire conflict: %v", err)
		}
		https.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(https, "GET /hello HTTP/1.1\r\nHost: app.edge.test\r\nConnection: close\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(https), nil)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("HTTPS during wire conflict: %v %v", response, err)
		}
		response.Body.Close()
		https.Close()
		conn := pg(t, startup(sslRequest))
		reply := make([]byte, 1)
		if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 'S' {
			t.Fatalf("Postgres lost during wire conflict: %q %v", reply, err)
		}
		roundTrip(t, tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "pg.edge.test"}))
		// Releasing the old listener is enough: wire must bind automatically,
		// and the later TLS/frame tests use this recovered listener.
		wireLn.Close()
		select {
		case <-wireBound:
		case <-time.After(15 * time.Second):
			t.Fatal("wire did not recover after migration")
		}
	})

	t.Run("postgres plaintext refused", func(t *testing.T) {
		conn := pg(t, append(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 17}, 196608), "user\x00x\x00\x00"...))
		reply, _ := io.ReadAll(conn)
		if len(reply) == 0 || reply[0] != 'E' || !bytes.Contains(reply, []byte("C28000\x00")) || !bytes.Contains(reply, []byte("sslmode=require")) {
			t.Fatalf("reply = %q", reply)
		}
	})

	t.Run("postgres sslrequest", func(t *testing.T) {
		conn := pg(t, startup(gssencRequest))
		reply := make([]byte, 1)
		if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 'N' {
			t.Fatalf("GSSENCRequest reply = %q, %v", reply, err)
		}
		conn.Write(startup(sslRequest))
		if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 'S' {
			t.Fatalf("SSLRequest reply = %q, %v", reply, err)
		}
		client := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "pg.edge.test"})
		roundTrip(t, client)
	})

	t.Run("postgres direct tls", func(t *testing.T) {
		client := tls.Client(pg(t), &tls.Config{RootCAs: roots, ServerName: "pg.edge.test", NextProtos: []string{"postgresql"}})
		roundTrip(t, client)
		roundTrip(t, tls.Client(dialPG(t, "::1"), &tls.Config{RootCAs: roots, ServerName: "pg.edge.test", NextProtos: []string{"postgresql"}}))
		// Direct TLS without the Postgres ALPN is closed before the backend.
		client = tls.Client(pg(t), &tls.Config{RootCAs: roots, ServerName: "pg.edge.test"})
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("direct TLS without ALPN was proxied")
		}
	})

	t.Run("postgres unknown sni", func(t *testing.T) {
		conn := pg(t, startup(sslRequest))
		io.ReadFull(conn, make([]byte, 1))
		if err := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "app.edge.test"}).Handshake(); err == nil {
			t.Fatal("handshake for a web-only hostname succeeded on :5432")
		}
	})

	t.Run("wire verified TLS preserves binary frames", func(t *testing.T) {
		client, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", wireLn.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "wire.edge.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		client.SetDeadline(time.Now().Add(10 * time.Second))
		// No Postgres negotiation or PROXY header may precede these frames.
		for _, frame := range [][]byte{{5, 0, 0, 0, 42, 0, 0, 0, 0}, {6, 0, 0, 0, 43, 0, 0, 0, 1, 255}} {
			if _, err := client.Write(frame); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(frame))
			if _, err := io.ReadFull(client, reply); err != nil || !bytes.Equal(reply, frame) {
				t.Fatalf("frame = %x, %v", reply, err)
			}
		}
		<-wireAccepted
	})
	t.Run("wire rejects plaintext and foreign SNI before backend", func(t *testing.T) {
		for _, host := range []string{"app.edge.test", "pg.edge.test", "unknown.edge.test", ""} {
			conn, err := net.DialTimeout("tcp", wireLn.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			config := &tls.Config{RootCAs: roots, ServerName: host}
			// Only this negative case bypasses local verification so an empty-SNI
			// ClientHello actually reaches the server's route check.
			if host == "" {
				config.InsecureSkipVerify = true
			}
			err = tls.Client(conn, config).Handshake()
			conn.Close()
			if err == nil || !strings.Contains(err.Error(), "remote error: tls:") {
				t.Fatalf("wire SNI %q: wanted server rejection, got %v", host, err)
			}
		}
		conn, err := net.DialTimeout("tcp", wireLn.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte{5, 0, 0, 0, 42, 0, 0, 0, 0})
		if _, err := conn.Read(make([]byte, 64)); err == nil {
			t.Fatal("wire accepted plaintext")
		}
		conn.Close()
		select {
		case <-wireAccepted:
			t.Fatal("rejected client reached backend")
		default:
		}
	})

	t.Run("wire backend loss withdraws public admission", func(t *testing.T) {
		if !firewallOpen.Load() {
			t.Fatal("wire admission never opened after readiness and bind")
		}
		for len(firewallClosed) > 0 {
			<-firewallClosed
		}
		wireBackend.Close()
		select {
		case <-firewallClosed:
		case <-time.After(15 * time.Second):
			t.Fatal("wire admission not withdrawn after backend loss")
		}
		if firewallOpen.Load() {
			t.Fatal("wire admission remains open after backend loss")
		}
	})

	t.Run("postgres cancel", func(t *testing.T) {
		request := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 16}, cancelRequest), 42)
		request = binary.BigEndian.AppendUint32(request, 7)
		release, err := e.pgKeys.add([8]byte(request[8:]), pgBackend)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		conn := pg(t, request)
		select {
		case got := <-pgGot:
			if !bytes.Equal(got, request) {
				t.Fatalf("backend got %x, want %x", got, request)
			}
			if got, want := <-pgHeaders, wantHeader(conn); !bytes.Equal(got, want) {
				t.Fatalf("PROXY header = %x, want %x", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("cancel request never reached the backend")
		}
	})

	cancel()
	if err := <-served; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

// echoBackend stands in for a plaintext Postgres server behind a PROXY v2
// header: it reports each connection's header on headers and its first read
// after the header on got, and echoes everything after the header back.
func echoBackend(t *testing.T) (port int, got, headers chan []byte) {
	ln := listen(t)
	got, headers = make(chan []byte, 8), make(chan []byte, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				header := make([]byte, 16)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				header = append(header, make([]byte, binary.BigEndian.Uint16(header[14:]))...)
				if _, err := io.ReadFull(conn, header[16:]); err != nil {
					return
				}
				headers <- header
				var first [8]byte
				if _, err := io.ReadFull(conn, first[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint32(first[:4]))
				if first[0] != 0 {
					size = 1 + int(binary.BigEndian.Uint32(first[1:5]))
				}
				if size < 8 || size > 64 {
					return
				}
				buf := append(first[:], make([]byte, size-8)...)
				if _, err := io.ReadFull(conn, buf[8:]); err != nil {
					return
				}
				got <- buf
				conn.Write(buf)
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got, headers
}

func TestProxyHeaderSendsMappedIPv4AsTCP4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 50000}
	dst := &net.TCPAddr{IP: net.ParseIP("::ffff:10.0.0.1"), Port: 5432}
	want := []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\xcb\x00\x71\x07\x0a\x00\x00\x01\xc3\x50\x15\x38")
	if got := proxyHeader(src, dst); !bytes.Equal(got, want) {
		t.Fatalf("header = %x, want %x", got, want)
	}
}

func appBackend() http.Handler {
	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, health.NewServer())
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s proto=%s path=%s spoofed=%s%s", r.Host, r.Header.Get("X-Forwarded-Proto"), r.URL.Path,
			r.Header.Get("X-Real-IP"), r.Header.Get("CF-Connecting-IP"))
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: hello\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		if websocket.Message.Receive(ws, &msg) == nil {
			websocket.Message.Send(ws, "echo "+msg)
		}
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && r.Header.Get("Content-Type") == "application/grpc" {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// finalizeLocation adds the order URL that Pebble leaves out of finalize
// replies; x/crypto/acme polls it while the order is processing, as it does
// with Let's Encrypt.
func finalizeLocation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/finalize-order/"); ok {
			w.Header().Set("Location", "https://"+r.Host+"/my-order/"+id)
		}
		next.ServeHTTP(w, r)
	})
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// startDNS answers every A query with 127.0.0.1 so Pebble reaches the edge.
func startDNS(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	server := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			})
		}
		w.WriteMsg(reply)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return ln.Addr().String()
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestSecureHeadersKeepBackendValues(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("Referrer-Policy", "same-origin")
	secureHeaders(h)
	if h.Get("X-Frame-Options") != "" || h.Get("Content-Security-Policy") != "default-src 'self'" || h.Get("Referrer-Policy") != "same-origin" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers = %v", h)
	}
}

func TestEdgeRefusesPublicNetBirdSetup(t *testing.T) {
	e := newEdge(t.TempDir(), nil)
	e.SetRoutes(map[string]int{netbirdHost: 1}, nil)
	for _, target := range []string{"/api/setup", "//api/./setup", "/api/setup/"} {
		r := httptest.NewRequest(http.MethodPost, "https://"+netbirdHost+target, nil)
		w := httptest.NewRecorder()
		e.serveHTTPS(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", target, w.Code)
		}
	}
}

// A backend that binds its port during the handoff window still gets the request.
func TestDialHandoffWaitsForBackend(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	go func() {
		time.Sleep(300 * time.Millisecond)
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return
		}
		defer ln.Close()
		if conn, err := ln.Accept(); err == nil {
			conn.Close()
		}
	}()
	conn, err := dialHandoff(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial during handoff: %v", err)
	}
	conn.Close()
}

// A held port gets no dial until its new task is ready, even while it already
// accepts connections.
func TestDialHandoffWaitsForHeldPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	handoff.Hold(port)
	released := make(chan struct{})
	go func() {
		time.Sleep(300 * time.Millisecond)
		close(released)
		handoff.Release(port)
	}()
	conn, err := dialHandoff(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial after release: %v", err)
	}
	conn.Close()
	select {
	case <-released:
	default:
		t.Fatal("dial finished before the port was released")
	}
}
