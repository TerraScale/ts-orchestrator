package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const public = "127.0.0.1:443"

var started = time.Now()

func step(name string, err error) {
	if err != nil {
		fmt.Printf("FAIL %s after %s: %v\n", name, time.Since(started).Round(time.Millisecond), err)
		os.Exit(1)
	}
	fmt.Printf("ok %s at %s\n", name, time.Since(started).Round(time.Millisecond))
}

type writers struct {
	mu            sync.Mutex
	owner, secret string
	epoch         int
}

func (s *writers) node(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TerraBase-Peer-Credential") != s.secret {
			http.Error(w, "unknown peer credential", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		owner, epoch := s.owner, s.epoch
		if r.URL.Path == "/v1/rollout/drain" {
			s.owner, s.epoch = r.URL.Query().Get("target"), epoch+1
		}
		s.mu.Unlock()
		switch {
		case r.URL.Path == "/v1/rollout/status":
			fmt.Fprintf(w, `{"node":%q,"owner":%q,"epoch":%d,"writer":%t,"ready":true}`, name, owner, epoch, owner == name)
		case r.URL.Path == "/v1/rollout/prime" || r.URL.Path == "/v1/rollout/drain":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodConnect && r.Header.Get(":protocol") == "websocket":
			w.WriteHeader(http.StatusOK)
			_ = http.NewResponseController(w).Flush()
			_, _ = io.Copy(flushed{w}, r.Body)
		default:
			fmt.Fprintf(w, "rest from %s", name)
		}
	})
}

type flushed struct{ http.ResponseWriter }

func (f flushed) Write(p []byte) (int, error) {
	n, err := f.ResponseWriter.Write(p)
	if err == nil {
		err = http.NewResponseController(f.ResponseWriter).Flush()
	}
	return n, err
}

type socket struct {
	reader io.Reader
	write  func([]byte) error
}

func (s socket) echo() error {
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	sent := append([]byte{0x81, 0x80 | 5}, mask...)
	for i, c := range []byte("hello") {
		sent = append(sent, c^mask[i%4])
	}
	if err := s.write(sent); err != nil {
		return err
	}
	got := make([]byte, len(sent))
	if _, err := io.ReadFull(s.reader, got); err != nil {
		return err
	}
	if !bytes.Equal(got, sent) {
		return fmt.Errorf("echoed %x for %x", got, sent)
	}
	return nil
}

func (s socket) ended() error {
	var timeout interface{ Timeout() bool }
	if n, err := s.reader.Read(make([]byte, 1)); n > 0 || errors.As(err, &timeout) && timeout.Timeout() {
		return fmt.Errorf("still open 5s after it opened (read %d bytes, %v)", n, err)
	}
	return nil
}

func openHTTP1(roots *x509.CertPool, host string) (socket, error) {
	conn, err := tls.Dial("tcp", public, &tls.Config{ServerName: host, RootCAs: roots, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return socket{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	encoded := base64.StdEncoding.EncodeToString(key)
	_, _ = fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", host, encoded)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return socket{}, err
	}
	accept := sha1.Sum([]byte(encoded + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(accept[:]) {
		return socket{}, fmt.Errorf("handshake answered %s", response.Status)
	}
	s := socket{reader, func(p []byte) error { _, err := conn.Write(p); return err }}
	return s, s.echo()
}

func openHTTP2(roots *x509.CertPool, host string) (socket, error) {
	conn, err := tls.Dial("tcp", public, &tls.Config{ServerName: host, RootCAs: roots, NextProtos: []string{"h2"}})
	if err != nil {
		return socket{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if _, err = io.WriteString(conn, http2.ClientPreface); err == nil {
		err = framer.WriteSettings()
	}
	if err != nil {
		return socket{}, err
	}
	frame, err := framer.ReadFrame()
	if settings, ok := frame.(*http2.SettingsFrame); err != nil || !ok {
		return socket{}, fmt.Errorf("no SETTINGS from the edge: %v", err)
	} else if enabled, _ := settings.Value(http2.SettingEnableConnectProtocol); enabled != 1 {
		return socket{}, errors.New("the edge does not advertise extended CONNECT")
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range [][2]string{{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "https"}, {":authority", host}, {":path", "/socket"}, {"sec-websocket-version", "13"}} {
		_ = encoder.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]})
	}
	if err = framer.WriteSettingsAck(); err == nil {
		err = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true})
	}
	if err != nil {
		return socket{}, err
	}
	var mu sync.Mutex
	locked := func(write func() error) error { mu.Lock(); defer mu.Unlock(); return write() }
	reader, pipe := io.Pipe()
	status := make(chan string, 1)
	go func() {
		defer close(status)
		for {
			frame, err := framer.ReadFrame()
			switch f := frame.(type) {
			case *http2.MetaHeadersFrame:
				select {
				case status <- f.PseudoValue("status"):
				default:
				}
			case *http2.DataFrame:
				if n := uint32(len(f.Data())); n > 0 {
					_, _ = pipe.Write(f.Data())
					_ = locked(func() error { return errors.Join(framer.WriteWindowUpdate(0, n), framer.WriteWindowUpdate(1, n)) })
				}
				if f.StreamEnded() {
					err = io.EOF
				}
			case *http2.RSTStreamFrame:
				err = fmt.Errorf("RST_STREAM %v", f.ErrCode)
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = locked(framer.WriteSettingsAck)
				}
			}
			if err != nil {
				pipe.CloseWithError(err)
				return
			}
		}
	}()
	if code := <-status; code != "200" {
		return socket{}, fmt.Errorf("extended CONNECT answered %q", code)
	}
	s := socket{reader, func(p []byte) error { return locked(func() error { return framer.WriteData(1, false, p) }) }}
	return s, s.echo()
}

func listening() bool {
	var metrics strings.Builder
	observability.WriteEdgeListenerMetrics(&metrics)
	return strings.Contains(metrics.String(), observability.Series("ts_orch_edge_listener_ready", "protocol", "https")+" 1\n")
}

func main() {
	state, ca, host := os.Args[1], os.Args[2], os.Args[3]
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	writer := &writers{owner: "n1", secret: hex.EncodeToString(secret), epoch: 1}
	nodes := []mesh.WorkerPeer{{Node: "n1", Address: "127.0.0.2"}, {Node: "n2", Address: "127.0.0.3"}}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	for _, node := range nodes {
		listener, err := net.Listen("tcp", net.JoinHostPort(node.Address, "8081"))
		step("writer stand-in "+node.Node+" on "+node.Address+":8081", err)
		go (&http.Server{Handler: writer.node(node.Node), Protocols: protocols}).Serve(listener)
	}
	regional := edge.New(state)
	regional.SetRoutes(map[string]int{host: 8080}, nil)
	step("SetRequestProofSecret", regional.SetRequestProofSecret(writer.secret))
	regional.SetRegionalNodes(func() []mesh.WorkerPeer { return nodes })
	control, err := net.Listen("tcp", "127.0.0.1:0")
	step("control port", err)
	go http.Serve(control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := regional.DrainRegionalNode(ctx, r.URL.Query().Get("node")); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}
	}))
	go regional.Run(context.Background())
	for begun := time.Now(); !listening(); runtime.Gosched() {
		if time.Since(begun) > 10*time.Second {
			step("edge serving :443", errors.New("no :443 listener after 10s"))
		}
	}
	pem, err := os.ReadFile(ca)
	roots := x509.NewCertPool()
	if err == nil && !roots.AppendCertsFromPEM(pem) {
		err = fmt.Errorf("no certificate in %s", ca)
	}
	step("edge serving :443 for "+host, err)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, public)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true, DialContext: dial}}
	rest := func(want string) error {
		response, err := client.Get("https://" + host + "/rest")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err == nil && (response.StatusCode != http.StatusOK || string(body) != want) {
			err = fmt.Errorf("answered %s %q, want 200 %q", response.Status, body, want)
		}
		return err
	}
	step("REST through regionalRoundTrip to the writer n1", rest("rest from n1"))
	h1, err := openHTTP1(roots, host)
	step("HTTP/1.1 WebSocket answered 101 and echoed a frame", err)
	h2, err := openHTTP2(roots, host)
	step("RFC 8441 WebSocket answered 200 and echoed a frame", err)
	drain, err := http.Get("http://" + control.Addr().String() + "/drain?node=n1")
	if err == nil {
		body, _ := io.ReadAll(drain.Body)
		if drain.StatusCode != http.StatusOK {
			err = fmt.Errorf("DrainRegionalNode within 5s: %s", strings.TrimSpace(string(body)))
		}
	}
	step("drain of the writer n1 with both WebSockets open", err)
	step("HTTP/1.1 WebSocket ended by the drain", h1.ended())
	step("RFC 8441 WebSocket ended by the drain", h2.ended())
	step("REST after the drain served by the new writer n2", rest("rest from n2"))
}
