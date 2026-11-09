package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestTerraBaseLoopbackRelaysExtendedConnectWebSocketsBesideREST(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	dial := terrabaseEdge(t, h2cUpstream(t, listen(t), func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			_, _ = io.WriteString(w, "rest "+r.Host+r.URL.RequestURI())
			return
		}
		if r.Header.Get(":protocol") != "websocket" || r.Host != terrabaseLoopback || r.URL.RequestURI() != "/v1/sql/socket?db=main" ||
			r.Header.Get("Sec-WebSocket-Protocol") != "terrabase.sql" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Sec-WebSocket-Protocol", "terrabase.sql")
		w.WriteHeader(http.StatusOK)
		flusher := http.NewResponseController(w)
		_ = flusher.Flush()
		frames := bufio.NewReader(r.Body)
		for {
			message, err := readWebSocketFrame(frames)
			if errors.Is(err, io.EOF) {
				_ = writeWebSocketFrame(w, "closed", false)
				return
			}
			if err != nil || writeWebSocketFrame(w, "echo "+message, false) != nil || flusher.Flush() != nil {
				return
			}
		}
	}))

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	rest := &http.Client{Transport: &http.Transport{Protocols: protocols, DialContext: dial}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+terrabaseLoopback+"/v1/databases?limit=1", nil)
	response, err := rest.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "rest "+terrabaseLoopback+"/v1/databases?limit=1" {
		t.Fatalf("REST = %d %q", response.StatusCode, body)
	}

	upload, send := io.Pipe()
	request, _ = http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+terrabaseLoopback+"/v1/sql/socket?db=main", upload)
	request.Header.Set(":protocol", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Protocol", "terrabase.sql")
	response, err = tunnelTransport{dial: dial}.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Sec-WebSocket-Protocol") != "terrabase.sql" {
		t.Fatalf("extended CONNECT = %d %v", response.StatusCode, response.Header)
	}
	frames := bufio.NewReader(response.Body)
	for _, message := range []string{"select 1", "select 2"} {
		if err := writeWebSocketFrame(send, message, true); err != nil {
			t.Fatal(err)
		}
		if reply, err := readWebSocketFrame(frames); err != nil || reply != "echo "+message {
			t.Fatalf("reply = %q, %v", reply, err)
		}
	}
	send.Close()
	if reply, err := readWebSocketFrame(frames); err != nil || reply != "closed" {
		t.Fatalf("after half-close = %q, %v", reply, err)
	}
	if _, err := frames.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end = %v", err)
	}
}

func TestTerraBaseTunnelEchoesTenMegabytesBothWays(t *testing.T) {
	t.Parallel()
	dial := terrabaseEdge(t, h2cUpstream(t, listen(t), echoTunnel))
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	send, response := openTunnel(t, ctx, dial)
	payload := make([]byte, 10<<20+123)
	_, _ = rand.Read(payload)
	go func() {
		for rest := payload; len(rest) > 0; {
			n := min(len(rest), 1000+int(rest[0])*37)
			if _, err := send.Write(rest[:n]); err != nil {
				return
			}
			rest = rest[n:]
		}
		send.Close()
	}()
	echoed, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || sha256.Sum256(echoed) != sha256.Sum256(payload) {
		t.Fatalf("echoed %d of %d bytes: %v", len(echoed), len(payload), err)
	}
}

func TestTerraBaseTunnelDeliversToASlowReader(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 10<<20)
	_, _ = rand.Read(payload)
	dial := terrabaseEdge(t, h2cUpstream(t, listen(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, bytes.NewReader(payload))
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	send, response := openTunnel(t, ctx, dial)
	defer send.Close()
	time.Sleep(200 * time.Millisecond)
	received, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("received %d of %d bytes: %v", len(received), len(payload), err)
	}
}

func TestTerraBaseTunnelEndsWhenTerraBaseEndsFirst(t *testing.T) {
	t.Parallel()
	dial := terrabaseEdge(t, h2cUpstream(t, listen(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "bye")
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	send, response := openTunnel(t, ctx, dial)
	defer send.Close()
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(got) != "bye" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestTerraBaseTunnelCancelsWithoutLeakingGoroutines(t *testing.T) {
	ended := make(chan struct{}, 32)
	dial := terrabaseEdge(t, h2cUpstream(t, listen(t), func(w http.ResponseWriter, r *http.Request) {
		defer func() { ended <- struct{}{} }()
		echoTunnel(w, r)
	}))
	before := runtime.NumGoroutine()
	for i := range 20 {
		ctx, cancel := context.WithCancel(t.Context())
		send, response := openTunnel(t, ctx, dial)
		_, _ = send.Write([]byte("hello"))
		if _, err := io.ReadFull(response.Body, make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		cancel()
		response.Body.Close()
		send.Close()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Fatalf("TerraBase never saw tunnel %d end", i)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+10 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+10 {
		stacks := make([]byte, 1<<20)
		t.Fatalf("goroutines %d -> %d\n%s", before, after, stacks[:runtime.Stack(stacks, true)])
	}
}

func TestTerraBaseTunnelOutlivesTheHandshakeDeadline(t *testing.T) {
	handshake := tunnelHandshake
	tunnelHandshake = 200 * time.Millisecond
	t.Cleanup(func() { tunnelHandshake = handshake })
	dial := terrabaseEdge(t, h2cUpstream(t, listen(t), echoTunnel))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	send, response := openTunnel(t, ctx, dial)
	defer response.Body.Close()
	time.Sleep(3 * tunnelHandshake)
	if _, err := send.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(response.Body, reply); err != nil || string(reply) != "late" {
		t.Fatalf("reply = %q, %v", reply, err)
	}
	send.Close()
}

func TestTerraBaseTunnelAppliesARepeatedInitialWindowOnce(t *testing.T) {
	t.Parallel()
	const window = 40000
	ln := listen(t)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
			return
		}
		framer := http2.NewFramer(conn, conn)
		initial := http2.Setting{ID: http2.SettingInitialWindowSize, Val: window}
		if framer.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1}, initial) != nil ||
			framer.WriteSettings(initial) != nil || framer.WriteWindowUpdate(0, 1<<20) != nil {
			return
		}
		received := 0
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.HeadersFrame:
				var block bytes.Buffer
				_ = hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block.Bytes(), EndHeaders: true})
			case *http2.DataFrame:
				received += len(f.Data())
				if received > window {
					_ = framer.WriteRSTStream(f.StreamID, http2.ErrCodeFlowControl)
					return
				}
				if f.StreamEnded() {
					_ = framer.WriteData(f.StreamID, true, []byte(strconv.Itoa(received)))
					return
				}
			}
		}
	}()
	dial := terrabaseEdge(t, ln.Addr().String())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	send, response := openTunnel(t, ctx, dial)
	go func() {
		_, _ = send.Write(make([]byte, window))
		send.Close()
	}()
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(got) != strconv.Itoa(window) {
		t.Fatalf("TerraBase received %q, %v", got, err)
	}
}

func TestTerraBaseTunnelWaitsForARestartingTerraBase(t *testing.T) {
	t.Parallel()
	reserved := listen(t)
	address := reserved.Addr().String()
	reserved.Close()
	dial := terrabaseEdge(t, address)
	restarted := time.AfterFunc(300*time.Millisecond, func() {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			t.Error(err)
			return
		}
		h2cUpstream(t, ln, echoTunnel)
	})
	t.Cleanup(func() { restarted.Stop() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	send, response := openTunnel(t, ctx, dial)
	defer response.Body.Close()
	defer send.Close()
	if _, err := send.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, reply); err != nil || string(reply) != "hello" {
		t.Fatalf("reply = %q, %v", reply, err)
	}
}

func TestPublicEdgeServesWebSocketsOverHTTP2(t *testing.T) {
	t.Parallel()
	app := httptest.NewServer(appBackend())
	t.Cleanup(app.Close)
	e := New(t.TempDir())
	e.SetRoutes(map[string]int{"app.edge.test": app.Listener.Addr().(*net.TCPAddr).Port}, nil)
	public := httptest.NewUnstartedServer(http.HandlerFunc(e.serveHTTPS))
	public.EnableHTTP2 = true
	public.StartTLS()
	t.Cleanup(public.Close)
	roots := x509.NewCertPool()
	roots.AddCert(public.Certificate())
	browser := tunnelTransport{dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		config := &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"h2"}}
		return (&tls.Dialer{Config: config}).DialContext(ctx, network, public.Listener.Addr().String())
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	connect := func(path string) (*io.PipeWriter, *http.Response) {
		upload, send := io.Pipe()
		request, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://app.edge.test"+path, upload)
		request.Header.Set(":protocol", "websocket")
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Origin", "https://app.edge.test")
		response, err := browser.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { send.Close(); response.Body.Close() })
		return send, response
	}

	send, response := connect("/ws")
	if response.StatusCode != http.StatusOK || response.Header.Get("Upgrade") != "" || response.Header.Get("Sec-WebSocket-Accept") != "" {
		t.Fatalf("extended CONNECT = %d %v", response.StatusCode, response.Header)
	}
	if err := writeWebSocketFrame(send, "ping", true); err != nil {
		t.Fatal(err)
	}
	if reply, err := readWebSocketFrame(bufio.NewReader(response.Body)); err != nil || reply != "echo ping" {
		t.Fatalf("reply = %q, %v", reply, err)
	}

	if _, response := connect("/"); response.StatusCode != http.StatusBadGateway {
		t.Fatalf("extended CONNECT to a page that answers 200 instead of upgrading = %d, want 502", response.StatusCode)
	}
}

func terrabaseEdge(t *testing.T, terrabase string) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	e := New(t.TempDir())
	e.terrabase = func() (string, error) { return terrabase, nil }
	ln := listen(t)
	go func() { _ = e.serveRegionalInternal(ln) }()
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}
}

func h2cUpstream(t *testing.T, ln net.Listener, handler http.HandlerFunc) string {
	upstream := httptest.NewUnstartedServer(handler)
	upstream.Listener.Close()
	upstream.Listener = ln
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	t.Cleanup(upstream.Close)
	return ln.Addr().String()
}

func echoTunnel(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	flusher := http.NewResponseController(w)
	_ = flusher.Flush()
	buffer := make([]byte, 7000)
	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			if _, werr := w.Write(buffer[:n]); werr != nil || flusher.Flush() != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func openTunnel(t *testing.T, ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (*io.PipeWriter, *http.Response) {
	t.Helper()
	upload, send := io.Pipe()
	request, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+terrabaseLoopback+"/v1/sql/socket", upload)
	request.Header.Set(":protocol", "websocket")
	response, err := tunnelTransport{dial: dial}.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("extended CONNECT = %d", response.StatusCode)
	}
	return send, response
}

func writeWebSocketFrame(w io.Writer, message string, masked bool) error {
	payload := []byte(message)
	frame := []byte{0x81, byte(len(payload))}
	if masked {
		mask := [4]byte{7, 1, 3, 9}
		frame[1] |= 0x80
		frame = append(frame, mask[:]...)
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	_, err := w.Write(append(frame, payload...))
	return err
}

func readWebSocketFrame(r *bufio.Reader) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", err
	}
	var mask []byte
	if head[1]&0x80 != 0 {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(r, mask); err != nil {
			return "", err
		}
	}
	payload := make([]byte, head[1]&0x7f)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}
	for i := range payload {
		if mask != nil {
			payload[i] ^= mask[i%4]
		}
	}
	return string(payload), nil
}
